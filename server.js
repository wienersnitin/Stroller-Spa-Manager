
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing.');
  process.exit(1);
}

if (!process.env.ADMIN_API_KEY) {
  console.error('ADMIN_API_KEY is missing.');
  process.exit(1);
}

if (!process.env.CUSTOMER_SESSION_SECRET) {
  console.error('CUSTOMER_SESSION_SECRET is missing.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const app = express();
app.set('trust proxy', 1);

const statuses = [
  'requested', 'confirmed', 'pickup_scheduled', 'received',
  'inspection', 'cleaning', 'drying', 'quality_check',
  'ready', 'completed', 'cancelled'
];

const ADMIN_COOKIE = 'spa_admin';
const CUSTOMER_COOKIE = 'spa_customer';
const ADMIN_SESSION_SECONDS = 8 * 60 * 60;
const CUSTOMER_SESSION_SECONDS = 7 * 24 * 60 * 60;

const id = prefix =>
  prefix + '-' + crypto.randomBytes(5).toString('hex').toUpperCase();

const addMonths = (d, m) => {
  const v = new Date(d);
  const day = v.getUTCDate();
  v.setUTCDate(1);
  v.setUTCMonth(v.getUTCMonth() + m);
  const last = new Date(
    Date.UTC(v.getUTCFullYear(), v.getUTCMonth() + 1, 0)
  ).getUTCDate();
  v.setUTCDate(Math.min(day, last));
  return v.toISOString().slice(0, 10);
};

const err = (res, code, message) =>
  res.status(code).json({ error: message });

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function normalizePhone(value) {
  let digits = String(value || '').replace(/\D/g, '');
  if (digits.length === 12 && digits.startsWith('91')) {
    digits = digits.slice(2);
  }
  return digits.length === 10 ? digits : '';
}

function hashToken(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function signToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret)
    .update(body).digest('hex');
  return `${body}.${signature}`;
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [body, signature] = parts;
  const expected = crypto.createHmac('sha256', secret)
    .update(body).digest('hex');

  if (!safeEqual(signature, expected)) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(body, 'base64url').toString('utf8')
    );
    if (!payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${escaped}=([^;]+)`));
  if (!match) return '';
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return '';
  }
}

function adminToken(expiry) {
  return signToken(
    { exp: expiry, role: 'admin' },
    process.env.ADMIN_API_KEY
  );
}

function verifyAdminCookie(req) {
  const payload = verifyToken(
    getCookie(req, ADMIN_COOKIE),
    process.env.ADMIN_API_KEY
  );
  return Boolean(payload && payload.role === 'admin');
}

function setAdminCookie(res, token) {
  res.cookie(ADMIN_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    maxAge: ADMIN_SESSION_SECONDS * 1000
  });
}

function clearAdminCookie(res) {
  res.clearCookie(ADMIN_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/'
  });
}

function setCustomerCookie(res, token) {
  res.cookie(CUSTOMER_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
    maxAge: CUSTOMER_SESSION_SECONDS * 1000
  });
}

function clearCustomerCookie(res) {
  res.clearCookie(CUSTOMER_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/'
  });
}

function verifyCustomer(req, res, next) {
  const payload = verifyToken(
    getCookie(req, CUSTOMER_COOKIE),
    process.env.CUSTOMER_SESSION_SECRET
  );

  if (!payload || payload.role !== 'customer' || !payload.customerId) {
    return err(res, 401, 'Please sign in to continue');
  }

  req.customerId = String(payload.customerId);
  next();
}

const admin = (req, res, next) => {
  if (verifyAdminCookie(req)) return next();

  const key = process.env.ADMIN_API_KEY || '';
  const got = req.get('X-Admin-Key') || '';

  if (key && safeEqual(got, key)) return next();
  return err(res, 401, 'Unauthorized');
};

async function findCustomerByPhone(client, phone) {
  const normalized = normalizePhone(phone);
  if (!normalized) return { customer: null, ambiguous: false };

  const result = await client.query(
    'SELECT id,name,phone,email,password_hash,account_activated_at FROM customers'
  );

  const matches = result.rows.filter(
    row => normalizePhone(row.phone) === normalized
  );

  if (matches.length > 1) {
    return { customer: null, ambiguous: true };
  }

  return { customer: matches[0] || null, ambiguous: false };
}

function makeActivationCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(10);
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += alphabet[bytes[i] % alphabet.length];
  }
  return code;
}

// --------------------------------------------------
// SECURITY HEADERS AND CORS - SINGLE CONFIGURATION
// --------------------------------------------------

const defaultOrigins = [
  'https://kidscompany.co.in',
  'https://www.kidscompany.co.in',
  'https://myspa.kidscompany.co.in',
  'https://spaadmin.kidscompany.co.in',
  'https://stroller-spa-customer-portal.onrender.com'
];

const environmentOrigins = [
  ...(process.env.PUBLIC_ORIGIN || '').split(','),
  ...(process.env.ALLOWED_ORIGINS || '').split(',')
]
  .map(origin => origin.trim().replace(/\/+$/, ''))
  .filter(Boolean);

const allowedOrigins = new Set([
  ...defaultOrigins,
  ...environmentOrigins
]);

app.use(helmet());

app.use(cors({
  origin(origin, callback) {
    if (!origin || origin === 'null') {
      return callback(null, true);
    }

    const cleanOrigin = origin.trim().replace(/\/+$/, '');

    const isAllowed =
      allowedOrigins.has(cleanOrigin) ||
      /^https:\/\/([a-z0-9-]+\.)*kidscompany\.co\.in$/i.test(cleanOrigin);

    if (isAllowed) {
      return callback(null, true);
    }

    console.warn('CORS blocked origin:', cleanOrigin);
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key'],
  optionsSuccessStatus: 204,
  maxAge: 86400
}));

// Shopify webhook must receive the untouched raw request body.
app.post(
  '/webhooks/shopify/orders-paid',
  express.raw({ type: 'application/json', limit: '1mb' }),
  async (req, res) => {
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
    if (!secret) return err(res, 503, 'Webhook not configured');

    const given = req.get('X-Shopify-Hmac-Sha256') || '';
    const expected = crypto.createHmac('sha256', secret)
      .update(req.body)
      .digest('base64');

    if (!safeEqual(given, expected)) {
      return err(res, 401, 'Invalid signature');
    }

    const eventId = req.get('X-Shopify-Webhook-Id') || '';
    if (!eventId) return err(res, 400, 'Missing webhook ID');

    const client = await pool.connect();

    try {
      const order = JSON.parse(req.body.toString('utf8'));
      await client.query('BEGIN');

      const event = await client.query(
        `INSERT INTO webhook_events(id)
         VALUES($1) ON CONFLICT(id) DO NOTHING RETURNING id`,
        [eventId]
      );

      if (!event.rowCount) {
        await client.query('COMMIT');
        return res.sendStatus(200);
      }

      if (order.financial_status !== 'paid') {
        throw new Error('Order not paid');
      }

      const phone = String(
        order.phone ||
        order.customer?.phone ||
        order.billing_address?.phone ||
        ''
      ).trim();

      const normalized = normalizePhone(phone);
      if (!normalized) throw new Error('Valid customer phone missing');

      const found = await findCustomerByPhone(client, phone);
      if (found.ambiguous) {
        throw new Error('Multiple customer records have this phone number');
      }

      let customerId;

      if (found.customer) {
        customerId = found.customer.id;
        await client.query(
          `UPDATE customers
           SET email=COALESCE(email,$1)
           WHERE id=$2`,
          [order.email || null, customerId]
        );
      } else {
        const name = [
          order.customer?.first_name,
          order.customer?.last_name
        ].filter(Boolean).join(' ') ||
          order.billing_address?.name ||
          'Shopify customer';

        const customer = await client.query(
          `INSERT INTO customers(name,phone,email)
           VALUES($1,$2,$3) RETURNING id`,
          [name, phone, order.email || null]
        );
        customerId = customer.rows[0].id;
      }

      const variants = {};

      if (process.env.SHOPIFY_STANDARD_VARIANT_ID) {
        variants[String(process.env.SHOPIFY_STANDARD_VARIANT_ID)] = {
          plan: 'standard', deep: 2, essential: 2, months: 12
        };
      }

      if (process.env.SHOPIFY_PREMIUM_VARIANT_ID) {
        variants[String(process.env.SHOPIFY_PREMIUM_VARIANT_ID)] = {
          plan: 'premium',
          deep: 4,
          essential: 2,
          months: Number(process.env.PREMIUM_MONTHS || 18)
        };
      }

      for (const line of order.line_items || []) {
        const cfg = variants[String(line.variant_id)];
        if (!cfg) continue;

        const quantity = Math.min(
          Math.max(Number(line.quantity) || 0, 0),
          20
        );

        for (let i = 0; i < quantity; i++) {
          const start = new Date().toISOString().slice(0, 10);
          await client.query(
            `INSERT INTO memberships
            (customer_id,code,plan,deep_total,essential_total,
             starts_at,expires_at,shopify_order_id)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
            [
              customerId,
              id('SPA'),
              cfg.plan,
              cfg.deep,
              cfg.essential,
              start,
              addMonths(start, cfg.months),
              String(order.id) + '-' + line.id + '-' + i
            ]
          );
        }
      }

      await client.query('COMMIT');
      return res.sendStatus(200);
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      console.error('Webhook processing failed:', e.message);
      return err(res, 422, 'Webhook could not be processed');
    } finally {
      client.release();
    }
  }
);

app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use('/api/public', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

app.use('/api/customer/login', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

app.use('/api/customer/activate', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

// Public booking form. A unique existing phone match is reused safely.
app.post('/api/public/bookings', async (req, res) => {
  const x = req.body || {};
  const s = k => String(x[k] || '').trim();
  const phone = s('phone');

  if (
    !x.consent ||
    s('name').length < 2 ||
    s('name').length > 120 ||
    !/^\+?[0-9() -]{10,18}$/.test(phone) ||
    !normalizePhone(phone) ||
    !s('category') ||
    !['essential', 'deep', 'repair', 'membership'].includes(s('service')) ||
    !/^\d{4}-\d{2}-\d{2}$/.test(s('preferred_date'))
  ) {
    return err(res, 400, 'Missing or invalid booking details');
  }

  const today = new Date().toISOString().slice(0, 10);
  if (s('preferred_date') < today) {
    return err(res, 400, 'Choose a future date');
  }

  if (s('notes').length > 1200 || s('model').length > 150) {
    return err(res, 400, 'Text too long');
  }

  const reference = id('BOOK');
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const found = await findCustomerByPhone(client, phone);
    if (found.ambiguous) {
      await client.query('ROLLBACK');
      return err(res, 409, 'Please contact support to verify this phone number');
    }

    let customerId;

    if (found.customer) {
      customerId = found.customer.id;
      await client.query(
        `UPDATE customers
         SET name=$1,email=COALESCE($2,email)
         WHERE id=$3`,
        [s('name'), s('email') || null, customerId]
      );
    } else {
      const c = await client.query(
        `INSERT INTO customers(name,phone,email)
         VALUES($1,$2,$3) RETURNING id`,
        [s('name'), phone, s('email') || null]
      );
      customerId = c.rows[0].id;
    }

    const g = await client.query(
      `INSERT INTO gear(customer_id,category,model)
       VALUES($1,$2,$3) RETURNING id`,
      [customerId, s('category'), s('model') || null]
    );

    await client.query(
      `INSERT INTO bookings
      (reference,customer_id,gear_id,service,preferred_date,
       fulfilment,notes,source)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        reference,
        customerId,
        g.rows[0].id,
        s('service'),
        s('preferred_date'),
        s('fulfilment') === 'pickup' ? 'pickup' : 'dropoff',
        s('notes') || null,
        s('source') || 'shopify'
      ]
    );

    await client.query('COMMIT');
    return res.status(201).json({ reference, status: 'requested' });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Booking create failed:', e.message);
    return err(res, 500, 'Booking could not be saved');
  } finally {
    client.release();
  }
});

// Staff login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' }
});

app.get('/login', (req, res) => {
  if (verifyAdminCookie(req)) return res.redirect('/');
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Stroller Spa Manager - Staff Login</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:#f6f7f9;font-family:Arial,sans-serif;color:#24323b}
main{width:100%;max-width:400px;padding:30px;border:1px solid #e5e7eb;border-radius:16px;background:white;box-shadow:0 10px 35px #24323b12}
h1{font-size:24px;margin:0 0 8px}
p{color:#687680;line-height:1.5}
label{display:block;margin:22px 0 8px;font-weight:bold}
input{width:100%;padding:13px;border:1px solid #cfd5da;border-radius:8px;font-size:16px}
button{width:100%;margin-top:18px;padding:13px;border:0;border-radius:8px;background:#e86d87;color:white;font-size:16px;font-weight:bold;cursor:pointer}
</style>
</head>
<body><main>
<h1>Stroller Spa Manager</h1>
<p>Enter your staff access key to continue.</p>
<form method="post" action="/login">
<label for="adminKey">Staff access key</label>
<input id="adminKey" name="adminKey" type="password" autocomplete="current-password" required maxlength="500">
<button type="submit">Sign in</button>
</form></main></body></html>`);
});

app.post('/login', loginLimiter, (req, res) => {
  const key = process.env.ADMIN_API_KEY || '';
  const got = String(req.body?.adminKey || '');

  if (!key || !safeEqual(got, key)) {
    return res.status(401).type('html').send(
      '<h2>Login failed</h2><p>The access key was incorrect.</p><a href="/login">Return to login</a>'
    );
  }

  const expiry = Math.floor(Date.now() / 1000) + ADMIN_SESSION_SECONDS;
  setAdminCookie(res, adminToken(expiry));
  res.setHeader('Cache-Control', 'no-store');
  return res.redirect(303, '/');
});

app.post('/logout', (req, res) => {
  clearAdminCookie(res);
  res.redirect(303, '/login');
});

// CUSTOMER ACCOUNT ACTIVATION
// Staff creates this code from the Admin Dashboard.
app.post('/api/admin/customers/:id/activation-code', admin, async (req, res) => {
  const customerId = String(req.params.id || '');
  if (!/^\d+$/.test(customerId)) {
    return err(res, 400, 'Invalid customer ID');
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const customer = await client.query(
      'SELECT id,name,phone,password_hash FROM customers WHERE id=$1 FOR UPDATE',
      [customerId]
    );

    if (!customer.rowCount) {
      await client.query('ROLLBACK');
      return err(res, 404, 'Customer not found');
    }

    if (customer.rows[0].password_hash) {
      await client.query('ROLLBACK');
      return err(res, 409, 'Customer account is already activated');
    }

    const code = makeActivationCode();
    const tokenHash = hashToken(code);

    await client.query(
      `UPDATE customer_activation_tokens
       SET used_at=CURRENT_TIMESTAMP
       WHERE customer_id=$1 AND used_at IS NULL`,
      [customerId]
    );

    const saved = await client.query(
      `INSERT INTO customer_activation_tokens
       (customer_id,token_hash,expires_at)
       VALUES($1,$2,CURRENT_TIMESTAMP + INTERVAL '24 hours')
       RETURNING expires_at`,
      [customerId, tokenHash]
    );

    await client.query('COMMIT');

    res.setHeader('Cache-Control', 'no-store');
    return res.status(201).json({
      customer_id: customerId,
      customer_name: customer.rows[0].name,
      phone: customer.rows[0].phone,
      activation_code: code,
      expires_at: saved.rows[0].expires_at,
      message: 'Show this code to the customer. It can be used only once.'
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Activation code create failed:', e.message);
    return err(res, 500, 'Could not create activation code');
  } finally {
    client.release();
  }
});

// Optional staff customer directory API.
app.get('/api/admin/customers', admin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.id,c.name,c.phone,c.email,c.created_at,
        c.account_activated_at,
        (SELECT COUNT(*)::int FROM bookings b WHERE b.customer_id=c.id) AS booking_count,
        (SELECT COUNT(*)::int FROM gear g WHERE g.customer_id=c.id) AS gear_count
      FROM customers c
      ORDER BY c.id DESC
      LIMIT 500
    `);
    res.setHeader('Cache-Control', 'no-store');
    res.json(result.rows);
  } catch (e) {
    console.error('Customer directory failed:', e.message);
    err(res, 500, 'Could not load customers');
  }
});

// Customer enters phone, activation code and chooses a password.
app.post('/api/customer/activate', async (req, res) => {
  const phone = String(req.body?.phone || '').trim();
  const code = String(req.body?.activation_code || '')
    .trim().toUpperCase().replace(/[\s-]/g, '');
  const password = String(req.body?.password || '');

  if (!normalizePhone(phone) || !/^[A-Z2-9]{8}$/.test(code)) {
    return err(res, 400, 'Enter a valid mobile number and activation code');
  }

  if (password.length < 8 || password.length > 128) {
    return err(res, 400, 'Password must be 8 to 128 characters');
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const found = await findCustomerByPhone(client, phone);

    if (found.ambiguous) {
      await client.query('ROLLBACK');
      return err(res, 409, 'Please contact support to verify your account');
    }

    if (!found.customer) {
      await client.query('ROLLBACK');
      return err(res, 400, 'Customer account or activation code is invalid');
    }

    const customer = await client.query(
      'SELECT * FROM customers WHERE id=$1 FOR UPDATE',
      [found.customer.id]
    );

    if (customer.rows[0].password_hash) {
      await client.query('ROLLBACK');
      return err(res, 409, 'This account is already activated');
    }

    const token = await client.query(
      `SELECT id FROM customer_activation_tokens
       WHERE customer_id=$1 AND token_hash=$2
       AND used_at IS NULL AND expires_at>CURRENT_TIMESTAMP
       FOR UPDATE`,
      [customer.rows[0].id, hashToken(code)]
    );

    if (!token.rowCount) {
      await client.query('ROLLBACK');
      return err(res, 400, 'Activation code is invalid or expired');
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await client.query(
      `UPDATE customers
       SET password_hash=$1,account_activated_at=CURRENT_TIMESTAMP
       WHERE id=$2`,
      [passwordHash, customer.rows[0].id]
    );

    await client.query(
      `UPDATE customer_activation_tokens
       SET used_at=CURRENT_TIMESTAMP WHERE id=$1`,
      [token.rows[0].id]
    );

    await client.query('COMMIT');

    const expiry = Math.floor(Date.now() / 1000) + CUSTOMER_SESSION_SECONDS;
    const session = signToken({
      role: 'customer',
      customerId: String(customer.rows[0].id),
      exp: expiry
    }, process.env.CUSTOMER_SESSION_SECRET);

    setCustomerCookie(res, session);
    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      activated: true,
      customer: {
        id: customer.rows[0].id,
        name: customer.rows[0].name,
        phone: customer.rows[0].phone
      }
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Customer activation failed:', e.message);
    return err(res, 500, 'Could not activate account');
  } finally {
    client.release();
  }
});

// Customer login using mobile number and password.
app.post('/api/customer/login', async (req, res) => {
  const phone = String(req.body?.phone || '').trim();
  const password = String(req.body?.password || '');

  if (!normalizePhone(phone) || !password || password.length > 128) {
    return err(res, 400, 'Enter your mobile number and password');
  }

  const client = await pool.connect();

  try {
    const found = await findCustomerByPhone(client, phone);

    if (found.ambiguous) {
      return err(res, 401, 'Mobile number or password is incorrect');
    }

    if (!found.customer || !found.customer.password_hash) {
      return err(res, 401, 'Account not activated or login details incorrect');
    }

    const valid = await bcrypt.compare(
      password,
      found.customer.password_hash
    );

    if (!valid) {
      return err(res, 401, 'Mobile number or password is incorrect');
    }

    const expiry = Math.floor(Date.now() / 1000) + CUSTOMER_SESSION_SECONDS;
    const session = signToken({
      role: 'customer',
      customerId: String(found.customer.id),
      exp: expiry
    }, process.env.CUSTOMER_SESSION_SECRET);

    setCustomerCookie(res, session);
    res.setHeader('Cache-Control', 'no-store');

    return res.json({
      logged_in: true,
      customer: {
        id: found.customer.id,
        name: found.customer.name,
        phone: found.customer.phone,
        email: found.customer.email
      }
    });
  } catch (e) {
    console.error('Customer login failed:', e.message);
    return err(res, 500, 'Could not sign in');
  } finally {
    client.release();
  }
});

app.post('/api/customer/logout', (req, res) => {
  clearCustomerCookie(res);
  res.json({ logged_out: true });
});

app.get('/api/customer/me', verifyCustomer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,name,phone,email,created_at,account_activated_at
       FROM customers WHERE id=$1`,
      [req.customerId]
    );

    if (!result.rowCount) return err(res, 404, 'Customer not found');
    res.setHeader('Cache-Control', 'no-store');
    res.json(result.rows[0]);
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not load customer profile');
  }
});

// Update customer name and email. Phone changes are intentionally disabled.
app.patch('/api/customer/profile', verifyCustomer, async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = String(req.body?.email || '').trim();

  if (name.length < 2 || name.length > 120) {
    return err(res, 400, 'Enter a valid name');
  }

  if (email.length > 180 ||
      (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
    return err(res, 400, 'Enter a valid email address');
  }

  try {
    const result = await pool.query(
      `UPDATE customers SET name=$1,email=$2
       WHERE id=$3
       RETURNING id,name,phone,email`,
      [name, email || null, req.customerId]
    );

    if (!result.rowCount) return err(res, 404, 'Customer not found');
    res.json(result.rows[0]);
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not update profile');
  }
});

// Customer baby gear belongs only to the signed-in customer.
app.get('/api/customer/gear', verifyCustomer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,category,brand,model,serial,purchase_date,image_url,created_at
       FROM gear WHERE customer_id=$1 ORDER BY id DESC`,
      [req.customerId]
    );
    res.setHeader('Cache-Control', 'no-store');
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not load baby gear');
  }
});

app.post('/api/customer/gear', verifyCustomer, async (req, res) => {
  const category = String(req.body?.category || '').trim();
  const brand = String(req.body?.brand || '').trim();
  const model = String(req.body?.model || '').trim();
  const serial = String(req.body?.serial || '').trim();
  const purchaseDate = String(req.body?.purchase_date || '').trim();
  const imageUrl = String(req.body?.image_url || '').trim();

  if (!category || category.length > 100 ||
      brand.length > 100 || model.length > 150 ||
      serial.length > 120 || imageUrl.length > 1000) {
    return err(res, 400, 'Please check the baby gear details');
  }

  if (purchaseDate && !/^\d{4}-\d{2}-\d{2}$/.test(purchaseDate)) {
    return err(res, 400, 'Invalid purchase date');
  }

  if (imageUrl && !/^https:\/\/\S+$/i.test(imageUrl)) {
    return err(res, 400, 'Image URL must use HTTPS');
  }

  try {
    const result = await pool.query(
      `INSERT INTO gear
       (customer_id,category,brand,model,serial,purchase_date,image_url)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING id,category,brand,model,serial,purchase_date,image_url,created_at`,
      [
        req.customerId,
        category,
        brand || null,
        model || null,
        serial || null,
        purchaseDate || null,
        imageUrl || null
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error('Gear create failed:', e.message);
    err(res, 500, 'Could not save baby gear');
  }
});

// Booking list includes the latest job status for live tracking.
app.get('/api/customer/bookings', verifyCustomer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        b.id,b.reference,b.service,b.preferred_date,b.fulfilment,
        b.notes,b.status,b.created_at,
        g.category AS gear_category,g.brand AS gear_brand,
        g.model AS gear_model,g.image_url AS gear_image,
        j.id AS job_id,j.status AS job_status,j.technician,
        j.inspection_notes,j.add_on_amount,j.completed_at
       FROM bookings b
       LEFT JOIN gear g ON g.id=b.gear_id
       LEFT JOIN jobs j ON j.booking_id=b.id
       WHERE b.customer_id=$1
       ORDER BY b.id DESC`,
      [req.customerId]
    );
    res.setHeader('Cache-Control', 'no-store');
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not load bookings');
  }
});

app.get('/api/customer/memberships', verifyCustomer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,code,plan,deep_total,essential_total,
        COALESCE(deep_used,0) AS deep_used,
        COALESCE(essential_used,0) AS essential_used,
        starts_at,expires_at,created_at
       FROM memberships
       WHERE customer_id=$1
       ORDER BY id DESC`,
      [req.customerId]
    );
    res.setHeader('Cache-Control', 'no-store');
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not load memberships');
  }
});

// Payments are not connected to a payment/invoice table yet.
app.get('/api/customer/payments', verifyCustomer, async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    items: [],
    integrated: false,
    message: 'Payment history and invoices are not connected yet.'
  });
});

app.get('/api/customer/dashboard', verifyCustomer, async (req, res) => {
  try {
    const [customer, bookingStats, bookings, memberships, gearCount] =
      await Promise.all([
        pool.query(
          `SELECT id,name,phone,email
           FROM customers WHERE id=$1`,
          [req.customerId]
        ),
        pool.query(
          `SELECT
            COUNT(*)::int AS total_bookings,
            COUNT(*) FILTER (WHERE COALESCE(j.status,b.status)
              NOT IN ('completed','cancelled'))::int AS active_bookings,
            COUNT(*) FILTER (WHERE COALESCE(j.status,b.status)
              = 'completed')::int AS completed_services
           FROM bookings b
           LEFT JOIN jobs j ON j.booking_id=b.id
           WHERE b.customer_id=$1`,
          [req.customerId]
        ),
        pool.query(
          `SELECT b.id,b.reference,b.service,b.preferred_date,
            b.fulfilment,b.status,
            COALESCE(j.status,b.status) AS current_status,
            g.category AS gear_category,g.model AS gear_model
           FROM bookings b
           LEFT JOIN jobs j ON j.booking_id=b.id
           LEFT JOIN gear g ON g.id=b.gear_id
           WHERE b.customer_id=$1
           ORDER BY b.id DESC LIMIT 5`,
          [req.customerId]
        ),
        pool.query(
          `SELECT id,code,plan,deep_total,essential_total,
            COALESCE(deep_used,0) AS deep_used,
            COALESCE(essential_used,0) AS essential_used,
            starts_at,expires_at
           FROM memberships WHERE customer_id=$1
           ORDER BY id DESC`,
          [req.customerId]
        ),
        pool.query(
          'SELECT COUNT(*)::int AS count FROM gear WHERE customer_id=$1',
          [req.customerId]
        )
      ]);

    if (!customer.rowCount) return err(res, 404, 'Customer not found');

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      customer: customer.rows[0],
      stats: {
        ...bookingStats.rows[0],
        gear_count: gearCount.rows[0].count,
        membership_count: memberships.rowCount
      },
      recent_bookings: bookings.rows,
      memberships: memberships.rows
    });
  } catch (e) {
    console.error('Customer dashboard failed:', e.message);
    err(res, 500, 'Could not load customer dashboard');
  }
});

// ADMIN DASHBOARD DATA
app.get('/api/admin/dashboard', admin, async (req, res) => {
  try {
    const [b, m, recent] = await Promise.all([
      pool.query(
        'SELECT status,COUNT(*)::int AS count FROM bookings GROUP BY status'
      ),
      pool.query(
        'SELECT plan,COUNT(*)::int AS count FROM memberships GROUP BY plan'
      ),
      pool.query(
        `SELECT b.*,c.name,c.phone,g.category
         FROM bookings b
         JOIN customers c ON c.id=b.customer_id
         LEFT JOIN gear g ON g.id=b.gear_id
         ORDER BY b.id DESC LIMIT 100`
      )
    ]);

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      bookings: b.rows,
      memberships: m.rows,
      recent: recent.rows
    });
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not load dashboard');
  }
});

app.get('/api/admin/bookings', admin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        b.id,b.reference,b.customer_id,b.gear_id,b.membership_id,
        b.service,b.preferred_date,b.fulfilment,b.notes,b.status,
        b.source,b.created_at,
        c.name AS customer_name,c.phone AS customer_phone,
        c.email AS customer_email,
        g.category AS gear_category,g.model AS gear_model,
        g.serial AS gear_serial,
        j.id AS job_id,j.status AS job_status
      FROM bookings b
      JOIN customers c ON c.id=b.customer_id
      LEFT JOIN gear g ON g.id=b.gear_id
      LEFT JOIN jobs j ON j.booking_id=b.id
      ORDER BY b.id DESC LIMIT 300
    `);
    res.setHeader('Cache-Control', 'no-store');
    res.json(result.rows);
  } catch (e) {
    console.error('Bookings list failed:', e.message);
    err(res, 500, 'Could not load bookings');
  }
});

app.get('/api/admin/jobs', admin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        j.id AS job_id,j.status AS job_status,j.technician,
        j.inspection_notes,j.add_on_amount,j.completed_at,
        j.created_at AS job_created_at,
        b.id AS booking_id,b.reference,b.service,b.preferred_date,
        b.fulfilment,b.notes AS booking_notes,b.status AS booking_status,
        b.membership_id,
        c.id AS customer_id,c.name AS customer_name,
        c.phone AS customer_phone,c.email AS customer_email,
        g.id AS gear_id,g.category AS gear_category,
        g.model AS gear_model,g.serial AS gear_serial
      FROM jobs j
      JOIN bookings b ON b.id=j.booking_id
      JOIN customers c ON c.id=b.customer_id
      LEFT JOIN gear g ON g.id=b.gear_id
      ORDER BY j.id DESC LIMIT 300
    `);
    res.setHeader('Cache-Control', 'no-store');
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not load job cards');
  }
});

app.get('/api/admin/memberships', admin, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT m.*,c.name,c.phone
       FROM memberships m
       JOIN customers c ON c.id=m.customer_id
       ORDER BY m.id DESC LIMIT 200`
    );
    res.setHeader('Cache-Control', 'no-store');
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not load memberships');
  }
});

// Confirm booking
app.post('/api/admin/bookings/:id/confirm', admin, async (req, res) => {
  try {
    const b = await pool.query(
      'SELECT * FROM bookings WHERE id=$1',
      [req.params.id]
    );
    if (!b.rowCount) return err(res, 404, 'Booking not found');
    if (b.rows[0].status !== 'requested') {
      return err(res, 409, 'Not a new request');
    }

    await pool.query(
      "UPDATE bookings SET status='confirmed' WHERE id=$1",
      [req.params.id]
    );
    res.json({ status: 'confirmed' });
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not confirm booking');
  }
});

// Create job card
app.post('/api/admin/bookings/:id/job', admin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const b = await client.query(
      'SELECT * FROM bookings WHERE id=$1 FOR UPDATE',
      [req.params.id]
    );

    if (!b.rowCount) {
      await client.query('ROLLBACK');
      return err(res, 404, 'Booking not found');
    }

    if (!['confirmed', 'received'].includes(b.rows[0].status)) {
      await client.query('ROLLBACK');
      return err(res, 409, 'Booking must be confirmed');
    }

    const j = await client.query(
      'INSERT INTO jobs(booking_id) VALUES($1) RETURNING id',
      [b.rows[0].id]
    );

    await client.query(
      "UPDATE bookings SET status='received' WHERE id=$1",
      [b.rows[0].id]
    );

    await client.query('COMMIT');
    res.status(201).json({ job_id: j.rows[0].id });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e.code === '23505') return err(res, 409, 'Job already exists');
    console.error(e);
    err(res, 500, 'Could not create job');
  } finally {
    client.release();
  }
});

// Update job status
app.post('/api/admin/jobs/:id/status', admin, async (req, res) => {
  const status = String(req.body?.status || '');
  if (!statuses.includes(status)) return err(res, 400, 'Invalid status');

  try {
    const j = await pool.query(
      'SELECT * FROM jobs WHERE id=$1',
      [req.params.id]
    );

    if (!j.rowCount) return err(res, 404, 'Job not found');
    if (['completed', 'cancelled'].includes(j.rows[0].status)) {
      return err(res, 409, 'Job closed');
    }
    if (status === 'completed') {
      return err(res, 400, 'Use complete endpoint for balance deduction');
    }

    await pool.query(
      'UPDATE jobs SET status=$1 WHERE id=$2',
      [status, req.params.id]
    );
    res.json({ status });
  } catch (e) {
    console.error(e);
    err(res, 500, 'Could not update job');
  }
});

// Assign membership to job
app.post('/api/admin/jobs/:id/assign-membership', admin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const jr = await client.query(
      `SELECT j.*,b.id AS booking_id,b.customer_id,b.service,b.membership_id
       FROM jobs j JOIN bookings b ON b.id=j.booking_id
       WHERE j.id=$1 FOR UPDATE`,
      [req.params.id]
    );

    if (!jr.rowCount) {
      await client.query('ROLLBACK');
      return err(res, 404, 'Job not found');
    }

    const job = jr.rows[0];
    const mr = await client.query(
      'SELECT * FROM memberships WHERE id=$1 FOR UPDATE',
      [Number(req.body?.membership_id)]
    );
    const m = mr.rows[0];

    if (!m || String(m.customer_id) !== String(job.customer_id)) {
      await client.query('ROLLBACK');
      return err(res, 400, 'Membership does not belong to customer');
    }

    if (job.status === 'completed') {
      await client.query('ROLLBACK');
      return err(res, 409, 'Job completed');
    }

    if (!['essential', 'deep', 'membership'].includes(job.service)) {
      await client.query('ROLLBACK');
      return err(res, 400, 'Not eligible');
    }

    await client.query(
      'UPDATE bookings SET membership_id=$1 WHERE id=$2',
      [m.id, job.booking_id]
    );

    await client.query('COMMIT');
    res.json({ assigned: true });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(e);
    err(res, 500, 'Could not assign membership');
  } finally {
    client.release();
  }
});

// Complete job and deduct membership credit.
app.post('/api/admin/jobs/:id/complete', admin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const jr = await client.query(
      `SELECT j.*,b.membership_id,b.service,b.customer_id,
        b.id AS booking_id
       FROM jobs j JOIN bookings b ON b.id=j.booking_id
       WHERE j.id=$1 FOR UPDATE`,
      [req.params.id]
    );

    if (!jr.rowCount) throw new Error('Job not found');

    const job = jr.rows[0];
    if (job.status === 'completed') throw new Error('Already completed');

    const cleaning = String(req.body?.cleaning_type || job.service);
    if (!['deep', 'essential', 'repair'].includes(cleaning)) {
      throw new Error('Invalid cleaning type');
    }

    if (job.membership_id) {
      if (cleaning === 'repair') {
        throw new Error('Repairs cannot consume cleaning entitlements');
      }

      const mr = await client.query(
        'SELECT * FROM memberships WHERE id=$1 FOR UPDATE',
        [job.membership_id]
      );
      const m = mr.rows[0];

      if (!m || String(m.customer_id) !== String(job.customer_id)) {
        throw new Error('Invalid membership');
      }

      const today = new Date().toISOString().slice(0, 10);
      const starts = String(m.starts_at).slice(0, 10);
      const expires = String(m.expires_at).slice(0, 10);

      if (today < starts || today > expires) {
        throw new Error('Membership expired or inactive');
      }

      const col = cleaning === 'deep' ? 'deep' : 'essential';
      const upd = await client.query(
        `UPDATE memberships
         SET ${col}_used=COALESCE(${col}_used,0)+1
         WHERE id=$1 AND COALESCE(${col}_used,0)<${col}_total`,
        [m.id]
      );

      if (!upd.rowCount) {
        throw new Error('No remaining ' + cleaning + ' credits');
      }

      await client.query(
        `INSERT INTO redemptions(membership_id,job_id,service)
         VALUES($1,$2,$3)`,
        [m.id, job.id, cleaning]
      );
    }

    await client.query(
      `UPDATE jobs SET status='completed',
       completed_at=CURRENT_TIMESTAMP WHERE id=$1`,
      [job.id]
    );

    await client.query(
      `UPDATE bookings SET status='completed' WHERE id=$1`,
      [job.booking_id]
    );

    await client.query('COMMIT');
    res.json({ completed: true, cleaning_type: cleaning });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    err(res, 409, e.message);
  } finally {
    client.release();
  }
});

// Serve existing staff dashboard after staff login.
app.get('/', (req, res) => {
  if (!verifyAdminCookie(req)) return res.redirect('/login');
  res.setHeader('Cache-Control', 'no-store');
  res.removeHeader('Content-Security-Policy');
  res.sendFile(process.cwd() + '/stroller-spa-manager.html');
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (e) {
    console.error('Health DB check failed:', {
      message: e.message,
      code: e.code
    });
    res.status(503).json({ ok: false, database: 'disconnected' });
  }
});

app.use((error, req, res, next) => {
  console.error('Request error:', error.message);
  if (res.headersSent) return next(error);
  return err(res, 500, 'Server could not process the request');
});

const server = app.listen(
  Number(process.env.PORT || 3000),
  () => console.log('Stroller Spa API listening')
);

process.on('SIGTERM', () => {
  server.close(() => pool.end().finally(() => process.exit(0)));
});
