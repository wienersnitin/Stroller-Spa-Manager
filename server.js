
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing. Set it in Render Environment.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

const app = express();

const statuses = [
  'requested', 'confirmed', 'pickup_scheduled', 'received',
  'inspection', 'cleaning', 'drying', 'quality_check',
  'ready', 'completed', 'cancelled'
];

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

app.use(helmet());

app.use(cors({
  origin: (process.env.PUBLIC_ORIGIN || 'https://kidscompany.co.in')
    .split(',')
    .map(x => x.trim())
}));

// Shopify paid-order webhook
app.post(
  '/webhooks/shopify/orders-paid',
  express.raw({ type: 'application/json', limit: '1mb' }),
  async (req, res) => {
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
    if (!secret) return err(res, 503, 'Webhook not configured');

    const given = req.get('X-Shopify-Hmac-Sha256') || '';
    const expected = crypto
      .createHmac('sha256', secret)
      .update(req.body)
      .digest('base64');

    if (
      given.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected))
    ) {
      return err(res, 401, 'Invalid signature');
    }

    const eventId = req.get('X-Shopify-Webhook-Id') || '';
    if (!eventId) return err(res, 400, 'Missing webhook ID');

    const client = await pool.connect();

    try {
      const order = JSON.parse(req.body.toString('utf8'));

      await client.query('BEGIN');

      const seen = await client.query(
        'SELECT id FROM webhook_events WHERE id=$1',
        [eventId]
      );

      if (seen.rowCount) {
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

      if (!phone) throw new Error('Customer phone missing');

      const name = [
        order.customer?.first_name,
        order.customer?.last_name
      ].filter(Boolean).join(' ') ||
        order.billing_address?.name ||
        'Shopify customer';

      const customer = await client.query(
        'INSERT INTO customers(name,phone,email) VALUES($1,$2,$3) RETURNING id',
        [name, phone, order.email || null]
      );

      const customerId = customer.rows[0].id;

      const variants = {
        [String(process.env.SHOPIFY_STANDARD_VARIANT_ID)]: {
          plan: 'standard',
          deep: 2,
          essential: 2,
          months: 12
        },
        [String(process.env.SHOPIFY_PREMIUM_VARIANT_ID)]: {
          plan: 'premium',
          deep: 4,
          essential: 2,
          months: Number(process.env.PREMIUM_MONTHS || 18)
        }
      };

      for (const line of order.line_items || []) {
        const cfg = variants[String(line.variant_id)];
        if (!cfg) continue;

        for (let i = 0; i < Math.min(Number(line.quantity) || 0, 20); i++) {
          const start = new Date().toISOString().slice(0, 10);

          await client.query(
            `INSERT INTO memberships
            (customer_id,code,plan,deep_total,essential_total,starts_at,expires_at,shopify_order_id)
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

      await client.query(
        'INSERT INTO webhook_events(id) VALUES($1)',
        [eventId]
      );

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

app.use('/api/public', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

// Public booking form
app.post('/api/public/bookings', async (req, res) => {
  const x = req.body || {};
  const s = k => String(x[k] || '').trim();

  if (
    !x.consent ||
    s('name').length < 2 ||
    s('name').length > 120 ||
    !/^\+?[0-9() -]{10,18}$/.test(s('phone')) ||
    !s('category') ||
    !['essential', 'deep', 'repair', 'membership'].includes(s('service')) ||
    !/^\d{4}-\d{2}-\d{2}$/.test(s('preferred_date'))
  ) {
    return err(res, 400, 'Missing or invalid booking details');
  }

  if (s('preferred_date') < new Date().toISOString().slice(0, 10)) {
    return err(res, 400, 'Choose a future date');
  }

  if (s('notes').length > 1200 || s('model').length > 150) {
    return err(res, 400, 'Text too long');
  }

  const reference = id('BOOK');
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const c = await client.query(
      'INSERT INTO customers(name,phone,email) VALUES($1,$2,$3) RETURNING id',
      [s('name'), s('phone'), s('email') || null]
    );

    const g = await client.query(
      'INSERT INTO gear(customer_id,category,model) VALUES($1,$2,$3) RETURNING id',
      [c.rows[0].id, s('category'), s('model') || null]
    );

    await client.query(
      `INSERT INTO bookings
      (reference,customer_id,gear_id,service,preferred_date,fulfilment,notes,source)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        reference,
        c.rows[0].id,
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

// Basic admin API key protection
const admin = (req, res, next) => {
  const key = process.env.ADMIN_API_KEY || '';
  const got = req.get('X-Admin-Key') || '';

  if (
    !key ||
    got.length !== key.length ||
    !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(key))
  ) {
    return err(res, 401, 'Unauthorized');
  }

  next();
};

// Dashboard data
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

// Membership list
app.get('/api/admin/memberships', admin, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT m.*,c.name,c.phone
       FROM memberships m
       JOIN customers c ON c.id=m.customer_id
       ORDER BY m.id DESC LIMIT 200`
    );
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
      'SELECT j.* FROM jobs j WHERE j.id=$1',
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

// Assign membership to a job
app.post('/api/admin/jobs/:id/assign-membership', admin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const jr = await client.query(
      `SELECT j.*,b.customer_id,b.service,b.membership_id
       FROM jobs j
       JOIN bookings b ON b.id=j.booking_id
       WHERE j.id=$1 FOR UPDATE`,
      [req.params.id]
    );

    if (!jr.rowCount) {
      await client.query('ROLLBACK');
      return err(res, 404, 'Job not found');
    }

    const job = jr.rows[0];

    const mr = await client.query(
      'SELECT * FROM memberships WHERE id=$1',
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

// Complete job and deduct membership credit
app.post('/api/admin/jobs/:id/complete', admin, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const jr = await client.query(
      `SELECT j.*,b.membership_id,b.service,b.customer_id,b.id AS booking_id
       FROM jobs j
       JOIN bookings b ON b.id=j.booking_id
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
         SET ${col}_used=${col}_used+1
         WHERE id=$1 AND ${col}_used<${col}_total`,
        [m.id]
      );

      if (!upd.rowCount) {
        throw new Error('No remaining ' + cleaning + ' credits');
      }

      await client.query(
        'INSERT INTO redemptions(membership_id,job_id,service) VALUES($1,$2,$3)',
        [m.id, job.id, cleaning]
      );
    }

    await client.query(
      "UPDATE jobs SET status='completed',completed_at=CURRENT_TIMESTAMP WHERE id=$1",
      [job.id]
    );

    await client.query(
      "UPDATE bookings SET status='completed' WHERE id=$1",
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

// Serve staff dashboard
app.get('/', (req, res) => {
  res.removeHeader('Content-Security-Policy');
  res.sendFile(process.cwd() + '/stroller-spa-manager.html');
});

// Database health check
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (e) {
    console.error('Health DB check failed:', e.message);
    res.status(503).json({ ok: false, database: 'disconnected' });
  }
});

const server = app.listen(
  Number(process.env.PORT || 3000),
  () => console.log('Stroller Spa API listening')
);

process.on('SIGTERM', () => {
  server.close(() => pool.end().finally(() => process.exit(0)));
});
