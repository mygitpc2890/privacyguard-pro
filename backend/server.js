require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { PrismaClient } = require('@prisma/client');
const { PrismaLibSQL } = require('@prisma/adapter-libsql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- Turso Database Setup (Simplified) ---
const adapter = new PrismaLibSQL({
  url: process.env.DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});
const prisma = new PrismaClient({ adapter });

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());

// ---------- Helpers ----------
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const checkTrialStatus = async (req, res, next) => {
  const subscription = await prisma.subscription.findUnique({
    where: { userId: req.userId },
  });
  if (!subscription) return res.status(403).json({ error: 'No subscription found' });
  const now = new Date();
  if (subscription.plan === 'free_trial' && new Date(subscription.trialEnd) < now) {
    return res.status(403).json({ 
      error: 'Your 1-year free trial has ended. Please upgrade.',
      expired: true 
    });
  }
  next();
};

// ---------- Routes ----------
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const trialDays = parseInt(process.env.TRIAL_DAYS) || 365;
    const trialEnd = new Date(Date.now() + trialDays * 24 * 60 * 60 * 1000);

    const user = await prisma.user.create({
      data: {
        email,
        password: hashed,
        name,
        subscription: {
          create: {
            plan: 'free_trial',
            trialEnd: trialEnd,
            isActive: true,
          },
        },
      },
      include: { subscription: true },
    });

    await prisma.user.update({
      where: { id: user.id },
      data: { verified: true },
    });

    res.status(201).json({ 
      message: 'Account created! You now have 1 year free.',
      trialEnd: trialEnd.toISOString(),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ 
      where: { email },
      include: { subscription: true },
    });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.verified) return res.status(401).json({ error: 'Please verify your email first' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = generateToken(user.id);
    const daysLeft = user.subscription?.trialEnd
      ? Math.ceil((new Date(user.subscription.trialEnd) - new Date()) / (1000 * 60 * 60 * 24))
      : 0;

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email },
      subscription: {
        plan: user.subscription?.plan || 'free_trial',
        daysLeft: daysLeft > 0 ? daysLeft : 0,
        isExpired: daysLeft <= 0,
        trialEnd: user.subscription?.trialEnd,
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/dashboard', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { subscription: true },
    });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const stats = await prisma.trackerStat.findMany({
      where: { userId, date: { gte: today } },
    });
    const totalBlocked = stats.reduce((sum, s) => sum + s.trackersBlocked, 0);
    const totalDataSaved = stats.reduce((sum, s) => sum + s.dataSavedMB, 0);
    const threats = stats.reduce((sum, s) => sum + s.threatsPrevented, 0);

    let daysLeft = 0;
    let isExpired = false;
    if (user.subscription?.trialEnd) {
      const now = new Date();
      const end = new Date(user.subscription.trialEnd);
      daysLeft = Math.ceil((end - now) / (1000 * 60 * 60 * 24));
      if (daysLeft <= 0) { isExpired = true; daysLeft = 0; }
    }

    const protectionScore = Math.min(98, 70 + Math.floor(totalBlocked / 100));

    res.json({
      trackersBlocked: totalBlocked || 0,
      dataSaved: totalDataSaved || 0,
      threatsPrevented: threats || 0,
      protectionScore: protectionScore,
      daysLeft: daysLeft,
      isExpired: isExpired,
      plan: user.subscription?.plan || 'free_trial',
      userName: user.name,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch dashboard' });
  }
});

app.post('/api/trackers/stats', verifyToken, async (req, res) => {
  try {
    const { trackersBlocked, threatsPrevented, dataSavedMB } = req.body;
    await prisma.trackerStat.create({
      data: {
        userId: req.userId,
        trackersBlocked: trackersBlocked || 0,
        threatsPrevented: threatsPrevented || 0,
        dataSavedMB: dataSavedMB || 0,
      },
    });
    res.status(201).json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to save stats' });
  }
});

app.get('/api/subscription/status', verifyToken, async (req, res) => {
  try {
    const subscription = await prisma.subscription.findUnique({
      where: { userId: req.userId },
    });
    if (!subscription) return res.status(404).json({ error: 'No subscription' });
    const daysLeft = Math.ceil((new Date(subscription.trialEnd) - new Date()) / (1000 * 60 * 60 * 24));
    res.json({
      plan: subscription.plan,
      daysLeft: daysLeft > 0 ? daysLeft : 0,
      isExpired: daysLeft <= 0,
      trialEnd: subscription.trialEnd,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch subscription' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 PrivacyGuard API running on port ${PORT}`);
});
