require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const app = express();
const port = Number(process.env.PORT || 5000);
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 32) throw new Error('Set JWT_SECRET to at least 32 characters.');
const dbFile = path.resolve(process.env.DATABASE_FILE || './data/micro-dilemma.sqlite');
fs.mkdirSync(path.dirname(dbFile), { recursive: true });
const db = new DatabaseSync(dbFile);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL, last_login INTEGER NOT NULL, total_reacted INTEGER NOT NULL DEFAULT 0,
 plan_tier TEXT NOT NULL DEFAULT 'Free Tier', plan_expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS dilemmas (
 id TEXT PRIMARY KEY, category TEXT NOT NULL, question TEXT NOT NULL, option_a TEXT NOT NULL,
 option_b TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'community', creator_id TEXT,
 created_at INTEGER NOT NULL, votes_a INTEGER NOT NULL DEFAULT 0, votes_b INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS votes (
 user_id TEXT NOT NULL, dilemma_id TEXT NOT NULL, choice TEXT NOT NULL CHECK(choice IN ('A','B')),
 created_at INTEGER NOT NULL, PRIMARY KEY(user_id,dilemma_id),
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
 FOREIGN KEY(dilemma_id) REFERENCES dilemmas(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS student_verifications (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL, contact_phone TEXT,
 institution TEXT NOT NULL, student_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 submitted_at INTEGER NOT NULL, reviewed_at INTEGER, reviewer_note TEXT,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS payments (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, plan TEXT NOT NULL, amount INTEGER NOT NULL,
 razorpay_order_id TEXT UNIQUE, razorpay_payment_id TEXT UNIQUE, status TEXT NOT NULL,
 created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS curated_oracle_history (
 question TEXT PRIMARY KEY, last_used_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dilemmas_created_idx ON dilemmas(created_at DESC);
`);
db.exec(`INSERT INTO curated_oracle_history(question,last_used_at)
 SELECT question,created_at FROM dilemmas WHERE source='curated'
 ON CONFLICT(question) DO UPDATE SET last_used_at=MAX(last_used_at,excluded.last_used_at)`);
const DAY = 86400000;
function transaction(callback) {
 return (...args) => {
  db.exec('BEGIN IMMEDIATE');
  try { const result = callback(...args); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
 };
}
function purgeExpired() { return db.prepare('DELETE FROM dilemmas WHERE created_at <= ?').run(Date.now() - DAY).changes; }
purgeExpired();
const expiryTimer = setInterval(purgeExpired, 60 * 60 * 1000);
expiryTimer.unref();
function publicDilemma(row) {
 return { id: row.id, category: row.category, question: row.question, optionA: row.option_a,
  optionB: row.option_b, source: row.source, createdAt: row.created_at, votesA: row.votes_a, votesB: row.votes_b };
}
function auth(req, res, next) {
 try {
  const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const claims = jwt.verify(raw, jwtSecret);
  req.user = db.prepare(`SELECT id,email,total_reacted,
   CASE WHEN plan_expires_at IS NOT NULL AND plan_expires_at <= ? THEN 'Free Tier' ELSE plan_tier END AS plan_tier,
   plan_expires_at FROM users WHERE id=?`).get(Date.now(), claims.sub);
  if (!req.user) return res.status(401).json({ error: 'Account not found.' });
  next();
 } catch { res.status(401).json({ error: 'Please log in again.' }); }
}
function owner(req, res, next) {
 const expected = process.env.ADMIN_API_KEY || '';
 const got = req.get('x-api-key') || '';
 if (!expected || expected.length < 32 || got.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected)))
  return res.status(401).json({ error: 'Owner authorization required.' });
 next();
}
app.use(helmet({
 contentSecurityPolicy: {
  directives: {
   defaultSrc: ["'self'"],
   scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://checkout.razorpay.com'],
   scriptSrcAttr: ["'unsafe-inline'"],
   styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
   fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
   imgSrc: ["'self'", 'data:', 'https:'],
   connectSrc: ["'self'", 'https://api.razorpay.com'],
   frameSrc: ["'self'", 'https://api.razorpay.com', 'https://checkout.razorpay.com'],
   formAction: ["'self'", 'https://api.razorpay.com', 'https://checkout.razorpay.com'],
   objectSrc: ["'none'"],
   baseUri: ["'self'"]
  }
 }
}));
app.use(cors({ origin: process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(x => x.trim()) : false }));
app.use('/api/payments/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '40kb' }));
app.use('/api', rateLimit({ windowMs: 60000, limit: 120, standardHeaders: true, legacyHeaders: false }));
app.get('/', (_req,res) => res.sendFile(path.join(__dirname, 'frontend.html')));
app.get('/index.html', (_req,res) => res.sendFile(path.join(__dirname, 'frontend.html')));
app.get('/api/health', (_req,res) => res.json({ status:'ok' }));
let aiReplenishmentPromise = null;
let aiReplenishmentBlockedUntil = 0;
const nonRetryableAICodes = new Set([
 'credit_balance_exhausted','insufficient_quota','organization_spend_limit_exceeded',
 'project_spend_limit_exceeded','organization_usage_limit_exceeded'
]);
function recordAIGenerationFailure(error, context) {
 const code=error.providerCode||'';
 if(nonRetryableAICodes.has(code)) aiReplenishmentBlockedUntil=Number.MAX_SAFE_INTEGER;
 else aiReplenishmentBlockedUntil=Date.now()+(error.retryAfterMs|| (error.providerStatus===429?60000:30000));
 const details=[error.providerStatus?`HTTP ${error.providerStatus}`:null,error.providerType?`type=${error.providerType}`:null,code?`code=${code}`:null,error.requestId?`requestId=${error.requestId}`:null].filter(Boolean).join(' ');
 console.error(context,details||error.name||'Unknown error');
}
const curatedOracleStarters=[
 {category:'Social',question:'Your friend shares an embarrassing typo from a private chat in a group. Do you:',optionA:'Message them privately so they can explain it first',optionB:'Let the group laugh and avoid making it a bigger deal'},
 {category:'Lifestyle',question:'You find a wallet with cash and an ID on a quiet street. Do you:',optionA:'Take it to a nearby police station or lost-and-found',optionB:'Contact the owner directly using the ID details'},
 {category:'Work',question:'A teammate is presenting an idea you helped develop but has not mentioned your contribution. Do you:',optionA:'Bring up your contribution during the discussion',optionB:'Talk to them privately after the meeting'},
 {category:'Ethics',question:'A cashier accidentally gives you too much change and the line is getting long. Do you:',optionA:'Point out the mistake before leaving',optionB:'Step aside and return the extra change quietly'},
 {category:'Hypothetical',question:'You can instantly learn one skill, but you must give up one hobby for a year. Do you:',optionA:'Choose a practical skill that helps your future',optionB:'Choose a fun skill that makes your free time better'},
 {category:'Social',question:'Your group cannot agree on a dinner place and one person has stopped suggesting ideas. Do you:',optionA:'Ask them directly what they would enjoy',optionB:'Choose a place and let them opt out if needed'},
 {category:'Lifestyle',question:'You have one free evening after a tiring week. Do you:',optionA:'Make plans with friends to recharge together',optionB:'Keep the evening free and recharge alone'},
 {category:'Work',question:'A meeting is running over time, but the final topic matters to only a few people. Do you:',optionA:'Stay so everyone can finish the discussion together',optionB:'Suggest moving the topic to a smaller follow-up'},
 {category:'Ethics',question:'You notice a small error in a public report that does not change its conclusion. Do you:',optionA:'Ask for a correction before sharing it',optionB:'Share it with a note explaining the minor error'},
 {category:'Hypothetical',question:'You get a free extra hour each day, but it must be used at the same time daily. Do you:',optionA:'Use it early in the morning for a calm start',optionB:'Use it late in the evening for personal projects'},
 {category:'Social',question:'A friend asks for honest feedback on a presentation just before they give it. Do you:',optionA:'Point out the biggest issue so they can adjust it',optionB:'Focus on what is working to build their confidence'},
 {category:'Lifestyle',question:'You can take a scenic route that adds an hour or a direct route that is less interesting. Do you:',optionA:'Take the scenic route and enjoy the journey',optionB:'Take the direct route and keep your plans on time'},
 {category:'Work',question:'Your team has one afternoon to improve a project. Do you:',optionA:'Polish one important feature until it is excellent',optionB:'Make smaller improvements across several features'},
 {category:'Ethics',question:'You find a phone left on a cafe table just after its owner has left. Do you:',optionA:'Give it to cafe staff to hold safely',optionB:'Stay nearby briefly and call the emergency contact'},
 {category:'Hypothetical',question:'You can revisit one ordinary day from last year, but cannot change anything. Do you:',optionA:'Choose a day spent with people you care about',optionB:'Choose a day when you felt proud of what you did'}
];
function seedCuratedOracleMinimum() {
 const cutoff=Date.now()-DAY;
 const active=db.prepare("SELECT question FROM dilemmas WHERE source IN ('ai','curated') AND created_at > ?").all(cutoff);
 const known=new Set(active.map(row=>row.question.toLowerCase()));
 const history=new Map(db.prepare('SELECT question,last_used_at FROM curated_oracle_history').all().map(row=>[row.question.toLowerCase(),row.last_used_at]));
 let remaining=Math.max(0,5-active.length), inserted=0;
 if(!remaining) return 0;
 const insert=db.prepare('INSERT INTO dilemmas(id,category,question,option_a,option_b,source,created_at) VALUES(?,?,?,?,?,?,?)');
 const remember=db.prepare('INSERT INTO curated_oracle_history(question,last_used_at) VALUES(?,?) ON CONFLICT(question) DO UPDATE SET last_used_at=excluded.last_used_at');
 const candidates=curatedOracleStarters.map((item,index)=>({item,index,lastUsedAt:history.get(item.question.toLowerCase())||0}))
  .filter(candidate=>!known.has(candidate.item.question.toLowerCase())&&candidate.lastUsedAt<=cutoff)
  .sort((a,b)=>a.lastUsedAt-b.lastUsedAt||a.index-b.index);
 transaction(()=>{
  for(const {item} of candidates) {
   if(!remaining) break;
   const normalized=item.question.toLowerCase();
   const createdAt=Date.now();
   insert.run(crypto.randomUUID(),item.category,item.question,item.optionA,item.optionB,'curated',createdAt);
   remember.run(item.question,createdAt);
   known.add(normalized);remaining--;inserted++;
  }
 })();
 return inserted;
}
async function ensureOracleFeed() {
 const activeAICount=db.prepare("SELECT COUNT(*) AS count FROM dilemmas WHERE source='ai' AND created_at > ?").get(Date.now()-DAY).count;
 if(activeAICount<5 && Date.now()>=aiReplenishmentBlockedUntil) {
  if(!aiReplenishmentPromise) {
   aiReplenishmentPromise=generateAIDilemmas(5).then(generated=>{
    if(generated.length===0) throw new Error('OpenAI returned no usable dilemmas');
    aiReplenishmentBlockedUntil=0;return generated;
   }).catch(error=>{recordAIGenerationFailure(error,'Could not replenish Oracle feed:');throw error;}).finally(()=>{aiReplenishmentPromise=null;});
  }
  try { await aiReplenishmentPromise; }
  catch {}
 }
 const inserted=seedCuratedOracleMinimum();
 if(inserted) console.log(`Added ${inserted} curated Oracle starter dilemmas.`);
}
app.get('/api/dilemmas', async (_req,res) => {
 const purgedCount = purgeExpired();
 await ensureOracleFeed();
 const rows = db.prepare('SELECT * FROM dilemmas WHERE created_at > ? ORDER BY created_at DESC').all(Date.now()-DAY);
 res.json({ dilemmas: rows.map(publicDilemma), purgedCount });
});
app.post('/api/auth/register', rateLimit({ windowMs: 900000, limit: 8 }), async (req,res) => {
 const email = String(req.body.email || '').trim().toLowerCase(); const password = String(req.body.password || '');
 if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 10 || password.length > 200)
  return res.status(400).json({ error:'Use a valid email and a password of at least 10 characters.' });
 const id = crypto.randomUUID();
 try { db.prepare('INSERT INTO users(id,email,password_hash,created_at,last_login) VALUES(?,?,?,?,?)').run(id,email,await bcrypt.hash(password,12),Date.now(),Date.now()); }
 catch { return res.status(409).json({ error:'An account with that email already exists.' }); }
 res.status(201).json(session(id));
});
app.post('/api/auth/login', rateLimit({ windowMs: 900000, limit: 12 }), async (req,res) => {
 const email=String(req.body.email||'').trim().toLowerCase(), password=String(req.body.password||'');
 const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if (!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Email or password is incorrect.'});
 db.prepare('UPDATE users SET last_login=? WHERE id=?').run(Date.now(),u.id); res.json(session(u.id));
});
function session(id) {
 const user=db.prepare(`SELECT id,email,total_reacted,
  CASE WHEN plan_expires_at IS NOT NULL AND plan_expires_at <= ? THEN 'Free Tier' ELSE plan_tier END AS plan_tier,
  plan_expires_at FROM users WHERE id=?`).get(Date.now(),id);
 const token=jwt.sign({sub:id},jwtSecret,{expiresIn:'30d'});
 const votedIds=Object.fromEntries(db.prepare('SELECT dilemma_id,choice FROM votes WHERE user_id=?').all(id).map(v=>[v.dilemma_id,v.choice]));
 return { token, user: { id:user.id,email:user.email,totalReacted:user.total_reacted,planTier:user.plan_tier,planExpiresAt:user.plan_expires_at,votedIds } };
}
app.get('/api/auth/me',auth,(req,res)=>{
 const votes=db.prepare(`SELECT d.id,d.category,d.question,d.option_a AS optionA,d.option_b AS optionB,
  v.choice,v.created_at AS votedAt,d.created_at AS createdAt
  FROM votes v JOIN dilemmas d ON d.id=v.dilemma_id
  WHERE v.user_id=? ORDER BY v.created_at DESC`).all(req.user.id);
 const votedIds=Object.fromEntries(votes.map(v=>[v.id,v.choice]));
 res.json({
  user:{id:req.user.id,email:req.user.email,totalReacted:req.user.total_reacted,planTier:req.user.plan_tier,planExpiresAt:req.user.plan_expires_at},
  votedIds,
  votingHistory:votes
 });
});
app.post('/api/dilemmas',auth,(req,res)=>{
 const {category,question,optionA,optionB}=req.body;
 if (!['Ethics','Lifestyle','Work','Social','Hypothetical'].includes(category) || ![question,optionA,optionB].every(v=>typeof v==='string'&&v.trim()) || question.length>400 || optionA.length>220 || optionB.length>220)
  return res.status(400).json({error:'Provide a category, question and two options within the length limits.'});
 const id=crypto.randomUUID(), createdAt=Date.now();
 db.prepare('INSERT INTO dilemmas(id,category,question,option_a,option_b,source,creator_id,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id,category.trim(),question.trim(),optionA.trim(),optionB.trim(),'community',req.user.id,createdAt);
 res.status(201).json({dilemma:publicDilemma(db.prepare('SELECT * FROM dilemmas WHERE id=?').get(id))});
});
app.post('/api/dilemmas/:id/vote',auth,(req,res)=>{
 const choice=req.body.choice;
 if (!['A','B'].includes(choice)) return res.status(400).json({error:'Choice must be A or B.'});
 const d=db.prepare('SELECT * FROM dilemmas WHERE id=? AND created_at>?').get(req.params.id,Date.now()-DAY);
 if (!d) return res.status(404).json({error:'Dilemma expired or not found.'});
 try { transaction(()=>{
  db.prepare('INSERT INTO votes(user_id,dilemma_id,choice,created_at) VALUES(?,?,?,?)').run(req.user.id,d.id,choice,Date.now());
  db.prepare(`UPDATE dilemmas SET votes_${choice==='A'?'a':'b'}=votes_${choice==='A'?'a':'b'}+1 WHERE id=?`).run(d.id);
  db.prepare('UPDATE users SET total_reacted=total_reacted+1 WHERE id=?').run(req.user.id);
 })(); } catch { return res.status(409).json({error:'You have already voted on this dilemma.'}); }
 res.json({dilemma:publicDilemma(db.prepare('SELECT * FROM dilemmas WHERE id=?').get(d.id))});
});
app.post('/api/student-verification',auth,(req,res)=>{
 const fullName=String(req.body.fullName||'').trim(), institution=String(req.body.institution||'').trim(), studentId=String(req.body.studentId||'').trim(), phone=String(req.body.phone||'').trim();
 if (!fullName||!institution||!studentId||fullName.length>120||institution.length>180||studentId.length>100||phone.length>30) return res.status(400).json({error:'Complete the student verification fields.'});
 const id=crypto.randomUUID();
 try { db.prepare('INSERT INTO student_verifications(id,user_id,full_name,contact_phone,institution,student_id,submitted_at) VALUES(?,?,?,?,?,?,?)').run(id,req.user.id,fullName,phone||null,institution,studentId,Date.now()); }
 catch { return res.status(409).json({error:'A student verification request already exists for this account.'}); }
 res.status(201).json({status:'pending',message:'Request submitted. Student Pro activates after review.'});
});
app.get('/api/student-verification',auth,(req,res)=>{
 const v=db.prepare('SELECT status,submitted_at,reviewer_note FROM student_verifications WHERE user_id=?').get(req.user.id);
 res.json({verification:v||null});
});
app.get('/api/admin/users',owner,(_req,res)=>{
 const users=db.prepare(`SELECT u.id,u.email,u.plan_tier AS planTier,u.total_reacted AS totalReacted,u.last_login AS lastLogin,v.status AS studentStatus FROM users u LEFT JOIN student_verifications v ON v.user_id=u.id ORDER BY u.created_at DESC`).all();
 res.json({users:users.map(u=>({...u,lastLogin:new Date(u.lastLogin).toISOString()})),stats:{purgedOver24h:0}});
});
app.get('/api/admin/dilemmas',owner,(_req,res)=>{
 const rows=db.prepare(`SELECT d.id,d.category,d.question,d.option_a AS optionA,d.option_b AS optionB,d.source,d.created_at AS createdAt,u.email AS creatorEmail
  FROM dilemmas d LEFT JOIN users u ON u.id=d.creator_id ORDER BY d.created_at DESC LIMIT 500`).all();
 res.json({dilemmas:rows});
});
app.get('/api/admin/student-verifications',owner,(_req,res)=>{
 res.json({requests:db.prepare(`SELECT v.id,v.full_name AS fullName,u.email,v.contact_phone AS phone,v.institution,v.student_id AS studentId,v.status,v.submitted_at AS submittedAt FROM student_verifications v JOIN users u ON u.id=v.user_id ORDER BY v.submitted_at`).all()});
});
app.post('/api/admin/student-verifications/:id/review',owner,(req,res)=>{
 const status=req.body.status;
 if (!['approved','rejected'].includes(status)) return res.status(400).json({error:'Status must be approved or rejected.'});
 const result=db.prepare('UPDATE student_verifications SET status=?,reviewed_at=?,reviewer_note=? WHERE id=?').run(status,Date.now(),String(req.body.note||'').slice(0,500),req.params.id);
 if (!result.changes) return res.status(404).json({error:'Verification request not found.'});
 res.json({status});
});
const PLAN_PRICES={student:4900,individual:9900};
const PLAN_NAMES={student:'Student Pro',individual:'Individual Pro'};
function razorpayClient() {
 if(!process.env.RAZORPAY_KEY_ID||!process.env.RAZORPAY_KEY_SECRET) return null;
 const Razorpay=require('razorpay');
 return new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET});
}
function signatureMatches(actual,expected) {
 if(typeof actual!=='string'||!/^[a-f0-9]{64}$/i.test(actual)) return false;
 const actualBytes=Buffer.from(actual,'hex'),expectedBytes=Buffer.from(expected,'hex');
 return actualBytes.length===expectedBytes.length&&crypto.timingSafeEqual(actualBytes,expectedBytes);
}
function activateCapturedPayment(payment) {
 if(!payment||payment.status!=='captured'||payment.currency!=='INR') return false;
 const initial=db.prepare('SELECT * FROM payments WHERE razorpay_order_id=?').get(payment.order_id);
 if(!initial||initial.amount!==payment.amount) return false;
 return transaction(()=>{
  const row=db.prepare('SELECT * FROM payments WHERE id=?').get(initial.id);
  if(!row||row.amount!==payment.amount) return false;
  if(row.status==='paid') return row.razorpay_payment_id===payment.id;
  if(row.razorpay_payment_id&&row.razorpay_payment_id!==payment.id) return false;
  const user=db.prepare('SELECT plan_expires_at FROM users WHERE id=?').get(row.user_id);
  if(!user) return false;
  const expiresAt=Math.max(Date.now(),Number(user.plan_expires_at)||0)+30*DAY;
  const tier=`${PLAN_NAMES[row.plan]} (${row.plan==='student'?'₹49':'₹99'} / 30 days)`;
  db.prepare("UPDATE payments SET status='paid',razorpay_payment_id=? WHERE id=?").run(payment.id,row.id);
  db.prepare('UPDATE users SET plan_tier=?,plan_expires_at=? WHERE id=?').run(tier,expiresAt,row.user_id);
  return true;
 })();
}
app.post('/api/subscription/upgrade',auth,async(req,res)=>{
 const plan=req.body.plan;
 if(!Object.hasOwn(PLAN_PRICES,plan)) return res.status(400).json({error:'Choose student or individual plan.'});
 const rzp=razorpayClient();
 if(!rzp) return res.status(503).json({error:'Payments are not configured. Add Razorpay test or live keys to the server .env.'});
 if(plan==='student') {
  const verification=db.prepare("SELECT status FROM student_verifications WHERE user_id=?").get(req.user.id);
  if(!verification||verification.status!=='approved') return res.status(403).json({error:'Student verification must be approved before checkout.'});
 }
 try {
  const amount=PLAN_PRICES[plan],receipt=crypto.randomUUID();
  const order=await rzp.orders.create({amount,currency:'INR',receipt,notes:{userId:req.user.id,plan}});
  db.prepare('INSERT INTO payments(id,user_id,plan,amount,razorpay_order_id,status,created_at) VALUES(?,?,?,?,?,?,?)').run(receipt,req.user.id,plan,amount,order.id,'created',Date.now());
  res.status(201).json({orderId:order.id,amount,currency:'INR',keyId:process.env.RAZORPAY_KEY_ID,plan,description:`${PLAN_NAMES[plan]} · 30 days`});
 } catch(error) {
  console.error('Razorpay order creation failed:',error.statusCode||error.name||'unknown error');
  res.status(502).json({error:'Could not start checkout. Please try again.'});
 }
});
app.post('/api/payments/verify',auth,async(req,res)=>{
 const {razorpay_order_id:orderId,razorpay_payment_id:paymentId,razorpay_signature:signature}=req.body||{};
 if(typeof orderId!=='string'||typeof paymentId!=='string'||typeof signature!=='string') return res.status(400).json({error:'Payment confirmation data is incomplete.'});
 const row=db.prepare('SELECT * FROM payments WHERE razorpay_order_id=? AND user_id=?').get(orderId,req.user.id);
 if(!row) return res.status(404).json({error:'Payment order was not found for this account.'});
 if(row.status==='paid'&&row.razorpay_payment_id===paymentId) return res.json({status:'paid'});
 const expected=crypto.createHmac('sha256',process.env.RAZORPAY_KEY_SECRET||'').update(`${row.razorpay_order_id}|${paymentId}`).digest('hex');
 if(!signatureMatches(signature,expected)) return res.status(400).json({error:'Razorpay payment signature is invalid.'});
 const rzp=razorpayClient();
 if(!rzp) return res.status(503).json({error:'Payment verification is not configured.'});
 try {
  const payment=await rzp.payments.fetch(paymentId);
  if(payment.order_id!==row.razorpay_order_id||payment.amount!==row.amount||payment.currency!=='INR') return res.status(400).json({error:'Payment details do not match this order.'});
  if(payment.status!=='captured') return res.status(202).json({status:'pending'});
  if(!activateCapturedPayment(payment)) return res.status(409).json({error:'Payment could not be applied to this account.'});
  res.json({status:'paid'});
 } catch(error) {
  console.error('Razorpay payment verification failed:',error.statusCode||error.name||'unknown error');
  res.status(502).json({error:'Payment was received but could not yet be verified. Confirmation will retry.'});
 }
});
app.get('/api/payments/orders/:orderId',auth,(req,res)=>{
 const row=db.prepare('SELECT status FROM payments WHERE razorpay_order_id=? AND user_id=?').get(req.params.orderId,req.user.id);
 if(!row) return res.status(404).json({error:'Payment order was not found for this account.'});
 res.json({status:row.status});
});
app.post('/api/payments/webhook',(req,res)=>{
 const secret=process.env.RAZORPAY_WEBHOOK_SECRET;
 if(!secret) return res.status(503).json({error:'Razorpay webhook secret is not configured.'});
 if(!Buffer.isBuffer(req.body)) return res.status(400).json({error:'Expected a raw webhook request body.'});
 const signature=req.get('x-razorpay-signature')||'';
 const expected=crypto.createHmac('sha256',secret).update(req.body).digest('hex');
 if(!signatureMatches(signature,expected)) return res.status(400).send('Invalid signature');
 let event;
 try { event=JSON.parse(req.body.toString('utf8')); }
 catch { return res.status(400).json({error:'Invalid webhook JSON.'}); }
 const payment=event?.payload?.payment?.entity;
 if(event.event==='payment.captured'&&payment) {
  if(!activateCapturedPayment(payment)) console.warn('Ignored captured Razorpay payment that did not match a pending local order.');
 } else if(event.event==='payment.failed'&&payment?.order_id) {
  db.prepare("UPDATE payments SET status='failed' WHERE razorpay_order_id=? AND status!='paid'").run(payment.order_id);
 }
 res.json({received:true});
});
async function generateAIDilemmas(count) {
 if (!process.env.OPENAI_API_KEY) throw new Error('AI generation is not configured. Set OPENAI_API_KEY on the server.');
 const response=await fetch('https://api.openai.com/v1/chat/completions',{method:'POST',headers:{Authorization:`Bearer ${process.env.OPENAI_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({model:process.env.OPENAI_MODEL||'gpt-4o-mini',response_format:{type:'json_object'},messages:[{role:'system',content:`Generate ${count} fresh, light-hearted, safe, binary everyday ethical/lifestyle dilemmas. Return JSON {"dilemmas":[{"category":"Social","question":"...","optionA":"...","optionB":"..."}]}. No identifying details, hate, graphic content, politics or medical advice. Keep choices balanced.`},{role:'user',content:'Create dilemmas for a general audience in India. Use natural English.'}]})});
 if(!response.ok) {
  let providerError={};
  try { providerError=(await response.json()).error||{}; } catch {}
  const safeValue=value=>typeof value==='string'&&/^[a-z0-9_.-]{1,100}$/i.test(value)?value:null;
  const retryHeader=response.headers.get('retry-after');
  let retryAfterMs=null;
  if(retryHeader!==null) {
   const seconds=Number(retryHeader);
   retryAfterMs=Number.isFinite(seconds)?Math.max(0,seconds*1000):Math.max(0,Date.parse(retryHeader)-Date.now());
  }
  const error=new Error('AI provider request failed');
  error.providerStatus=response.status;
  error.providerType=safeValue(providerError.type);
  error.providerCode=safeValue(providerError.code);
  error.requestId=safeValue(response.headers.get('x-request-id'));
  error.retryAfterMs=retryAfterMs;
  throw error;
 }
 const payload=await response.json(), parsed=JSON.parse(payload.choices[0].message.content);
 if(!Array.isArray(parsed.dilemmas)) throw new Error('AI provider returned an invalid dilemma list');
 const insert=db.prepare('INSERT INTO dilemmas(id,category,question,option_a,option_b,source,created_at) VALUES(?,?,?,?,?,?,?)');
 const categories=['Ethics','Lifestyle','Work','Social','Hypothetical'];
 const save=transaction(()=>parsed.dilemmas.slice(0,count).filter(d=>d?.question&&d?.optionA&&d?.optionB).map(d=>{const id=crypto.randomUUID();const category=categories.includes(d.category)?d.category:'Hypothetical';insert.run(id,category,String(d.question).slice(0,400),String(d.optionA).slice(0,220),String(d.optionB).slice(0,220),'ai',Date.now());return publicDilemma(db.prepare('SELECT * FROM dilemmas WHERE id=?').get(id));}));
 return save();
}
async function seedAIDilemmasOnStartup() {
 await ensureOracleFeed();
}
app.post('/api/ai/dilemmas',owner,async(req,res)=>{
 const count=Math.min(5,Math.max(1,Number(req.body.count)||3));
 try { const dilemmas=await generateAIDilemmas(count);aiReplenishmentBlockedUntil=0;res.status(201).json({dilemmas}); }
 catch(e) {
  recordAIGenerationFailure(e,'AI generation failed:');
  const status=e.message.includes('not configured')?503:e.providerStatus||502;
  res.status(status).json({error:'AI dilemma generation failed.',providerStatus:e.providerStatus||null,code:e.providerCode||null,type:e.providerType||null,requestId:e.requestId||null});
 }
});
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Internal server error.'});});
(async()=>{
 await seedAIDilemmasOnStartup();
 app.listen(port,()=>console.log(`Micro Dilemma API listening on ${port}`));
})();
