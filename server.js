require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const fetch      = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app = express();

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || '*',
    'https://torbem-12.github.io',
    'http://localhost:3000',
    'http://127.0.0.1:5500'
  ],
  credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// ── MONGODB ───────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB:', err.message));

// ── SCHEMAS ───────────────────────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  displayName:    { type: String, required: true, trim: true },
  email:          { type: String, required: true, unique: true, lowercase: true },
  password:       { type: String },
  piUid:          { type: String, unique: true, sparse: true },
  piUsername:     { type: String },
  tasksPosted:    { type: Number, default: 0 },
  tasksClaimed:   { type: Number, default: 0 },
  tasksCompleted: { type: Number, default: 0 },
  piEarned:       { type: Number, default: 0 },
  trustScore:     { type: Number, default: 0 },
  createdAt:      { type: Date, default: Date.now }
});

const TaskSchema = new mongoose.Schema({
  title:       { type: String, required: true, trim: true },
  category:    { type: String, required: true },
  bounty:      { type: Number, required: true, min: 0.1 },
  description: { type: String, required: true },
  posterName:  { type: String, required: true },
  posterId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  skills:      [String],
  claimsCount: { type: Number, default: 0 },
  maxClaims:   { type: Number, default: 1, min: 1 },
  deadline:    { type: Date, required: true },
  status:      { type: String, enum: ['open','in_progress','completed','cancelled'], default: 'open' },
  hot:         { type: Boolean, default: false },
  txid:        { type: String },
  claimants:   [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt:   { type: Date, default: Date.now }
});

const ClaimSchema = new mongoose.Schema({
  taskId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Task', required: true },
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status:    { type: String, enum: ['in_progress','submitted','approved','rejected'], default: 'in_progress' },
  createdAt: { type: Date, default: Date.now }
});

const SubmissionSchema = new mongoose.Schema({
  taskId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Task', required: true },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  workLink:    { type: String },
  description: { type: String, required: true },
  status:      { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  createdAt:   { type: Date, default: Date.now }
});

const PaymentSchema = new mongoose.Schema({
  paymentId: { type: String, required: true, unique: true },
  txid:      { type: String },
  userId:    { type: String },
  amount:    { type: Number },
  status:    { type: String, enum: ['pending','approved','completed','cancelled'], default: 'pending' },
  metadata:  mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now }
});

const User       = mongoose.model('User',       UserSchema);
const Task       = mongoose.model('Task',       TaskSchema);
const Claim      = mongoose.model('Claim',      ClaimSchema);
const Submission = mongoose.model('Submission', SubmissionSchema);
const Payment    = mongoose.model('Payment',    PaymentSchema);

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function makeToken(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '30d' });
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { displayName, email, password } = req.body;
    if (!displayName || !email || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (await User.findOne({ email }))
      return res.status(400).json({ error: 'Email already registered' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ displayName, email, password: hashed });
    res.status(201).json({ token: makeToken(user._id), user: safeUser(user) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: makeToken(user._id), user: safeUser(user) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/pi  — Pi Browser authentication
// Validates accessToken with Pi Network /v2/me before creating session
app.post('/api/auth/pi', async (req, res) => {
  try {
    const { piUid, piUsername, accessToken } = req.body;
    if (!piUid || !accessToken)
      return res.status(400).json({ error: 'piUid and accessToken required' });

    // ── VALIDATE TOKEN WITH PI NETWORK ──────────────────────────────────────
    // Per Pi SDK docs: GET https://api.minepi.com/v2/me
    // Authorization: Bearer <accessToken>
    // No session is created until this succeeds.
    const piRes = await fetch('https://api.minepi.com/v2/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!piRes.ok) {
      console.error('[Arena] Pi /v2/me validation failed:', piRes.status);
      return res.status(401).json({ error: 'Pi token validation failed' });
    }

    const piData = await piRes.json();

    // Ensure the UID in the token matches what the client sent
    if (piData.uid !== piUid) {
      return res.status(401).json({ error: 'Pi UID mismatch — possible spoofing attempt' });
    }

    // ── CREATE OR UPDATE USER ────────────────────────────────────────────────
    let user = await User.findOne({ piUid });
    if (!user) {
      const username = piData.username || piUsername || 'Pioneer_' + piUid.slice(-4);
      user = await User.create({
        displayName: username,
        email:       piUid + '@pi.network',
        piUid,
        piUsername:  piData.username || piUsername,
        trustScore:  20
      });
    }

    res.json({ token: makeToken(user._id), user: safeUser(user) });
  } catch (e) {
    console.error('[Arena] Pi auth error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

function safeUser(u) {
  return {
    id:             u._id,
    displayName:    u.displayName,
    email:          u.email,
    piUsername:     u.piUsername,
    piUid:          u.piUid,
    tasksPosted:    u.tasksPosted,
    tasksClaimed:   u.tasksClaimed,
    tasksCompleted: u.tasksCompleted,
    piEarned:       u.piEarned,
    trustScore:     u.trustScore
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// TASK ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/tasks
app.get('/api/tasks', async (req, res) => {
  try {
    const { category, sort, search } = req.query;
    const query = { status: 'open', deadline: { $gt: new Date() } };
    if (category && category !== 'All') query.category = category;
    if (search) query.$or = [
      { title:    { $regex: search, $options: 'i' } },
      { skills:   { $regex: search, $options: 'i' } },
      { category: { $regex: search, $options: 'i' } }
    ];
    let sortObj = { createdAt: -1 };
    if (sort === 'bounty')   sortObj = { bounty: -1 };
    if (sort === 'deadline') sortObj = { deadline: 1 };
    const tasks = await Task.find(query).sort(sortObj).limit(100);
    res.json({ tasks });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/tasks/:id
app.get('/api/tasks/:id', async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json({ task });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/tasks
app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { title, category, bounty, description, skills, maxClaims, deadlineHours, txid } = req.body;
    if (!title || !category || !bounty || !description)
      return res.status(400).json({ error: 'Missing required fields' });
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const deadline = new Date(Date.now() + (deadlineHours || 24) * 3600000);
    const task = await Task.create({
      title, category,
      bounty:     parseFloat(bounty),
      description,
      posterName: user.displayName,
      posterId:   req.userId,
      skills:     skills || [],
      maxClaims:  parseInt(maxClaims) || 1,
      deadline, txid,
      hot:        parseFloat(bounty) >= 10
    });
    await User.findByIdAndUpdate(req.userId, { $inc: { tasksPosted: 1 } });
    res.status(201).json({ task });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// CLAIM ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/tasks/:id/claim   — uses real MongoDB _id
app.post('/api/tasks/:id/claim', requireAuth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);
    if (!task)                             return res.status(404).json({ error: 'Task not found' });
    if (task.status !== 'open')            return res.status(400).json({ error: 'Task not available' });
    if (task.claimsCount >= task.maxClaims) return res.status(400).json({ error: 'Task is full' });
    if (task.claimants.includes(req.userId)) return res.status(400).json({ error: 'Already claimed' });
    if (String(task.posterId) === req.userId) return res.status(400).json({ error: 'Cannot claim your own task' });

    task.claimants.push(req.userId);
    task.claimsCount += 1;
    if (task.claimsCount >= task.maxClaims) task.status = 'in_progress';
    await task.save();

    await Claim.create({ taskId: task._id, userId: req.userId });
    await User.findByIdAndUpdate(req.userId, { $inc: { tasksClaimed: 1 } });

    res.json({ success: true, task });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/claims/mine
app.get('/api/claims/mine', requireAuth, async (req, res) => {
  try {
    const claims = await Claim.find({ userId: req.userId }).populate('taskId');
    res.json({ claims });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// SUBMISSION ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/submissions
app.post('/api/submissions', requireAuth, async (req, res) => {
  try {
    const { taskId, workLink, description } = req.body;
    if (!taskId || !description)
      return res.status(400).json({ error: 'taskId and description required' });
    const claim = await Claim.findOne({ taskId, userId: req.userId });
    if (!claim) return res.status(403).json({ error: 'You have not claimed this task' });
    const submission = await Submission.create({ taskId, userId: req.userId, workLink, description });
    await Claim.findByIdAndUpdate(claim._id, { status: 'submitted' });
    res.status(201).json({ submission });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/submissions/:id/approve
app.post('/api/submissions/:id/approve', requireAuth, async (req, res) => {
  try {
    const submission = await Submission.findById(req.params.id).populate('taskId');
    if (!submission) return res.status(404).json({ error: 'Submission not found' });
    const task = submission.taskId;
    if (String(task.posterId) !== req.userId)
      return res.status(403).json({ error: 'Only the task poster can approve' });
    submission.status = 'approved';
    await submission.save();
    await User.findByIdAndUpdate(submission.userId, {
      $inc: { tasksCompleted: 1, piEarned: task.bounty, trustScore: 10 }
    });
    await Claim.findOneAndUpdate(
      { taskId: task._id, userId: submission.userId },
      { status: 'approved' }
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// LEADERBOARD — returns only real users from MongoDB
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/leaderboard
app.get('/api/leaderboard', async (req, res) => {
  try {
    const users = await User.find({ tasksCompleted: { $gt: 0 } })
      .select('displayName piUsername tasksCompleted piEarned trustScore')
      .sort({ piEarned: -1 })
      .limit(20);
    res.json({ users });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// STATS
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/stats
app.get('/api/stats', async (req, res) => {
  try {
    const [liveTasks, totalTasks, totalUsers, piResult] = await Promise.all([
      Task.countDocuments({ status: 'open', deadline: { $gt: new Date() } }),
      Task.countDocuments(),
      User.countDocuments(),
      Task.aggregate([{ $group: { _id: null, total: { $sum: '$bounty' } } }])
    ]);
    res.json({
      liveTasks,
      totalTasks,
      totalUsers,
      totalPi: (piResult[0]?.total || 0).toFixed(1)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// PI PAYMENT ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/payments/approve
app.post('/api/payments/approve', async (req, res) => {
  try {
    const { paymentId, metadata } = req.body;
    if (!paymentId) return res.status(400).json({ error: 'paymentId required' });

    const piRes = await fetch(`https://api.minepi.com/v2/payments/${paymentId}/approve`, {
      method:  'POST',
      headers: { Authorization: `Key ${process.env.PI_API_KEY}` }
    });

    if (!piRes.ok) {
      const err = await piRes.text();
      console.error('[Arena] Pi approve failed:', err);
      return res.status(502).json({ error: 'Pi approval failed' });
    }

    const piData = await piRes.json();
    await Payment.findOneAndUpdate(
      { paymentId },
      { paymentId, status: 'approved', metadata, amount: piData.amount },
      { upsert: true }
    );
    res.json({ success: true, payment: piData });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/payments/complete
app.post('/api/payments/complete', async (req, res) => {
  try {
    const { paymentId, txid } = req.body;
    if (!paymentId || !txid) return res.status(400).json({ error: 'paymentId and txid required' });

    const piRes = await fetch(`https://api.minepi.com/v2/payments/${paymentId}/complete`, {
      method:  'POST',
      headers: {
        Authorization:  `Key ${process.env.PI_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ txid })
    });

    if (!piRes.ok) {
      const err = await piRes.text();
      console.error('[Arena] Pi complete failed:', err);
      return res.status(502).json({ error: 'Pi completion failed' });
    }

    const piData = await piRes.json();
    await Payment.findOneAndUpdate({ paymentId }, { status: 'completed', txid });
    res.json({ success: true, payment: piData });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/payments/incomplete
app.post('/api/payments/incomplete', async (req, res) => {
  try {
    const { paymentId } = req.body;
    if (!paymentId) return res.status(400).json({ error: 'paymentId required' });
    const existing = await Payment.findOne({ paymentId });
    if (existing && existing.status === 'approved') {
      // Was approved but never completed — attempt completion would happen via client retry
      console.log('[Arena] Incomplete payment was approved:', paymentId);
    } else {
      // Cancel it
      await fetch(`https://api.minepi.com/v2/payments/${paymentId}/cancel`, {
        method:  'POST',
        headers: { Authorization: `Key ${process.env.PI_API_KEY}` }
      }).catch(() => {});
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) =>
  res.json({ status: 'ok', time: new Date(), env: process.env.NODE_ENV || 'production' })
);

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Arena server running on port ${PORT}`));