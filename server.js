import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';

const app=express(),db=new Database(process.env.DB_PATH||'./stroller-spa.sqlite');
db.pragma('journal_mode = WAL');db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS gear(id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id), category TEXT NOT NULL, model TEXT, serial TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS memberships(id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL REFERENCES customers(id), gear_id INTEGER REFERENCES gear(id), code TEXT UNIQUE NOT NULL, plan TEXT NOT NULL, deep_total INTEGER NOT NULL, essential_total INTEGER NOT NULL, deep_used INTEGER DEFAULT 0, essential_used INTEGER DEFAULT 0, starts_at TEXT NOT NULL, expires_at TEXT NOT NULL, shopify_order_id TEXT UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY, reference TEXT UNIQUE NOT NULL, customer_id INTEGER NOT NULL REFERENCES customers(id), gear_id INTEGER REFERENCES gear(id), membership_id INTEGER REFERENCES memberships(id), service TEXT NOT NULL, preferred_date TEXT NOT NULL, fulfilment TEXT NOT NULL, notes TEXT, status TEXT DEFAULT 'requested', source TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, booking_id INTEGER UNIQUE NOT NULL REFERENCES bookings(id), status TEXT DEFAULT 'received', technician TEXT, inspection_notes TEXT, add_on_amount INTEGER DEFAULT 0, completed_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS redemptions(id INTEGER PRIMARY KEY, membership_id INTEGER NOT NULL REFERENCES memberships(id), job_id INTEGER UNIQUE NOT NULL REFERENCES jobs(id), service TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS webhook_events(id TEXT PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const statuses=['requested','confirmed','pickup_scheduled','received','inspection','cleaning','drying','quality_check','ready','completed','cancelled'];
const id=prefix=>prefix+'-'+crypto.randomBytes(5).toString('hex').toUpperCase();
const addMonths=(d,m)=>{const v=new Date(d);const day=v.getUTCDate();v.setUTCDate(1);v.setUTCMonth(v.getUTCMonth()+m);const last=new Date(Date.UTC(v.getUTCFullYear(),v.getUTCMonth()+1,0)).getUTCDate();v.setUTCDate(Math.min(day,last));return v.toISOString().slice(0,10)};
const err=(res,code,message)=>res.status(code).json({error:message});
app.use(helmet());app.use(cors({origin:(process.env.PUBLIC_ORIGIN||'https://kidscompany.co.in').split(',').map(x=>x.trim())}));
// Shopify webhook MUST receive raw bytes before JSON parsing.
app.post('/webhooks/shopify/orders-paid',express.raw({type:'application/json',limit:'1mb'}),(req,res)=>{
 const secret=process.env.SHOPIFY_WEBHOOK_SECRET;if(!secret)return err(res,503,'Webhook not configured');
 const given=req.get('X-Shopify-Hmac-Sha256')||'';const expected=crypto.createHmac('sha256',secret).update(req.body).digest('base64');
 if(given.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(given),Buffer.from(expected)))return err(res,401,'Invalid signature');
 const eventId=req.get('X-Shopify-Webhook-Id')||'';if(!eventId)return err(res,400,'Missing webhook ID');
 try{
 const order=JSON.parse(req.body.toString('utf8'));
 const run=db.transaction(()=>{
 if(db.prepare('SELECT id FROM webhook_events WHERE id=?').get(eventId))return;
 if(order.financial_status!=='paid')throw Error('Order not paid');
 const phone=String(order.phone||order.customer?.phone||order.billing_address?.phone||'').trim();if(!phone)throw Error('Customer phone missing');
 const name=[order.customer?.first_name,order.customer?.last_name].filter(Boolean).join(' ')||order.billing_address?.name||'Shopify customer';
 const cust=db.prepare('INSERT INTO customers(name,phone,email) VALUES(?,?,?)').run(name,phone,order.email||null).lastInsertRowid;
 const variants={[String(process.env.SHOPIFY_STANDARD_VARIANT_ID)]:{plan:'standard',deep:2,essential:2,months:12},[String(process.env.SHOPIFY_PREMIUM_VARIANT_ID)]:{plan:'premium',deep:4,essential:2,months:Number(process.env.PREMIUM_MONTHS||18)}};
 for(const line of order.line_items||[]){const cfg=variants[String(line.variant_id)];if(!cfg)continue;
 for(let i=0;i<Math.min(Number(line.quantity)||0,20);i++){
 const start=new Date().toISOString().slice(0,10);
 db.prepare('INSERT INTO memberships(customer_id,code,plan,deep_total,essential_total,starts_at,expires_at,shopify_order_id) VALUES(?,?,?,?,?,?,?,?)').run(cust,id('SPA'),cfg.plan,cfg.deep,cfg.essential,start,addMonths(start,cfg.months),String(order.id)+'-'+line.id+'-'+i);
 }}
 db.prepare('INSERT INTO webhook_events(id) VALUES(?)').run(eventId);
 });run();return res.sendStatus(200);
 }catch(e){console.error('Webhook processing failed:',e.message);return err(res,422,'Webhook could not be processed');}
});
app.use(express.json({limit:'30kb'}));
app.use('/api/public',rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:'draft-7',legacyHeaders:false}));
app.post('/api/public/bookings',(req,res)=>{
 const x=req.body||{};const s=k=>String(x[k]||'').trim();
 if(!x.consent||s('name').length<2||s('name').length>120||!/^\+?[0-9() -]{10,18}$/.test(s('phone'))||!s('category')||!['essential','deep','repair','membership'].includes(s('service'))||!/^\d{4}-\d{2}-\d{2}$/.test(s('preferred_date')))return err(res,400,'Missing or invalid booking details');
 if(s('preferred_date')<new Date().toISOString().slice(0,10))return err(res,400,'Choose a future date');
 if(s('notes').length>1200||s('model').length>150)return err(res,400,'Text too long');
 const reference=id('BOOK');
 const create=db.transaction(()=>{
 const customer=db.prepare('INSERT INTO customers(name,phone,email) VALUES(?,?,?)').run(s('name'),s('phone'),s('email')||null).lastInsertRowid;
 const gear=db.prepare('INSERT INTO gear(customer_id,category,model) VALUES(?,?,?)').run(customer,s('category'),s('model')||null).lastInsertRowid;
 // Membership IDs are intentionally NOT trusted from public requests: staff must verify ownership.
 db.prepare('INSERT INTO bookings(reference,customer_id,gear_id,service,preferred_date,fulfilment,notes,source) VALUES(?,?,?,?,?,?,?,?)').run(reference,customer,gear,s('service'),s('preferred_date'),s('fulfilment')==='pickup'?'pickup':'dropoff',s('notes')||null,s('source')||'shopify');
 });create();return res.status(201).json({reference,status:'requested'});
});
// Starter staff API only. Replace static API key with Shopify-authenticated embedded app sessions and role-based access before production.
const admin=(req,res,next)=>{const key=process.env.ADMIN_API_KEY||'';const got=req.get('X-Admin-Key')||'';if(!key||got.length!==key.length||!crypto.timingSafeEqual(Buffer.from(got),Buffer.from(key)))return err(res,401,'Unauthorized');next()};
app.get('/api/admin/dashboard',admin,(req,res)=>res.json({bookings:db.prepare('SELECT status,COUNT(*) count FROM bookings GROUP BY status').all(),memberships:db.prepare('SELECT plan,COUNT(*) count FROM memberships GROUP BY plan').all(),recent:db.prepare('SELECT b.*,c.name,c.phone,g.category FROM bookings b JOIN customers c ON c.id=b.customer_id LEFT JOIN gear g ON g.id=b.gear_id ORDER BY b.id DESC LIMIT 100').all()}));
app.get('/api/admin/memberships',admin,(req,res)=>res.json(db.prepare('SELECT m.*,c.name,c.phone FROM memberships m JOIN customers c ON c.id=m.customer_id ORDER BY m.id DESC LIMIT 200').all()));
app.post('/api/admin/bookings/:id/confirm',admin,(req,res)=>{const b=db.prepare('SELECT * FROM bookings WHERE id=?').get(req.params.id);if(!b)return err(res,404,'Booking not found');if(b.status!=='requested')return err(res,409,'Not a new request');db.prepare("UPDATE bookings SET status='confirmed' WHERE id=?").run(b.id);res.json({status:'confirmed'})});
app.post('/api/admin/bookings/:id/job',admin,(req,res)=>{const b=db.prepare('SELECT * FROM bookings WHERE id=?').get(req.params.id);if(!b)return err(res,404,'Booking not found');if(!['confirmed','received'].includes(b.status))return err(res,409,'Booking must be confirmed');try{const result=db.prepare('INSERT INTO jobs(booking_id) VALUES(?)').run(b.id);db.prepare("UPDATE bookings SET status='received' WHERE id=?").run(b.id);res.status(201).json({job_id:result.lastInsertRowid})}catch{return err(res,409,'Job already exists')}});
app.post('/api/admin/jobs/:id/status',admin,(req,res)=>{
 const status=String(req.body?.status||'');if(!statuses.includes(status))return err(res,400,'Invalid status');
 const job=db.prepare('SELECT j.*,b.membership_id,b.service FROM jobs j JOIN bookings b ON b.id=j.booking_id WHERE j.id=?').get(req.params.id);if(!job)return err(res,404,'Job not found');
 if(job.status==='completed'||job.status==='cancelled')return err(res,409,'Job closed');
 if(status==='completed')return err(res,400,'Use complete endpoint for balance deduction');
 db.prepare('UPDATE jobs SET status=? WHERE id=?').run(status,job.id);res.json({status});
});
app.post('/api/admin/jobs/:id/assign-membership',admin,(req,res)=>{
 const membershipId=Number(req.body?.membership_id),job=db.prepare('SELECT j.*,b.customer_id,b.service,b.membership_id FROM jobs j JOIN bookings b ON b.id=j.booking_id WHERE j.id=?').get(req.params.id);
 if(!job)return err(res,404,'Job not found');const m=db.prepare('SELECT * FROM memberships WHERE id=?').get(membershipId);
 if(!m||m.customer_id!==job.customer_id)return err(res,400,'Membership does not belong to customer');
 if(job.status==='completed')return err(res,409,'Job completed');
 if(!['essential','deep','membership'].includes(job.service))return err(res,400,'Not eligible');
 db.prepare('UPDATE bookings SET membership_id=? WHERE id=?').run(m.id,job.booking_id);res.json({assigned:true});
});
app.post('/api/admin/jobs/:id/complete',admin,(req,res)=>{
 try{const result=db.transaction(()=>{
 const job=db.prepare('SELECT j.*,b.membership_id,b.service,b.customer_id,b.booking_id as unused FROM jobs j JOIN bookings b ON b.id=j.booking_id WHERE j.id=?').get(req.params.id);
 if(!job)throw Error('Job not found');if(job.status==='completed')throw Error('Already completed');
 const cleaning=String(req.body?.cleaning_type||job.service);if(!['deep','essential','repair'].includes(cleaning))throw Error('Invalid cleaning type');
 if(job.membership_id){if(cleaning==='repair')throw Error('Repairs cannot consume cleaning entitlements');
 const m=db.prepare('SELECT * FROM memberships WHERE id=?').get(job.membership_id);if(!m||m.customer_id!==job.customer_id)throw Error('Invalid membership');
 const today=new Date().toISOString().slice(0,10);if(today<m.starts_at||today>m.expires_at)throw Error('Membership expired or inactive');
 const column=cleaning==='deep'?'deep':'essential';const update=db.prepare(`UPDATE memberships SET ${column}_used=${column}_used+1 WHERE id=? AND ${column}_used<${column}_total`).run(m.id);if(!update.changes)throw Error('No remaining '+cleaning+' credits');
 db.prepare('INSERT INTO redemptions(membership_id,job_id,service) VALUES(?,?,?)').run(m.id,job.id,cleaning);
 }
 db.prepare("UPDATE jobs SET status='completed',completed_at=CURRENT_TIMESTAMP WHERE id=?").run(job.id);db.prepare("UPDATE bookings SET status='completed' WHERE id=?").run(job.booking_id);return {completed:true,cleaning_type:cleaning};
 })();res.json(result)}catch(e){err(res,409,e.message)}
});
app.get('/', (req, res) => {
  res.removeHeader('Content-Security-Policy');
  res.sendFile(process.cwd() + '/stroller-spa-manager.html');
});

app.get('/health',(req,res)=>res.json({ok:true}));

app.listen(Number(process.env.PORT||3000),()=>console.log('Stroller Spa API listening'));
