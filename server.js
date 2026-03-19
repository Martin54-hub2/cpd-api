require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cpd-secret-key-change-in-production';
const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URL || 'mongodb://localhost:27017/cpd';

// ===== MIDDLEWARE =====
app.use(cors({
  origin: ['https://martin54-hub2.github.io', 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// ===== MONGOOSE CONNECT =====
mongoose.connect(MONGO_URI).then(() => console.log('MongoDB connected')).catch(err => console.error('MongoDB error:', err));

// ===== SCHEMAS =====
const officerSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  firstName: String,
  lastName: String,
  rank: { type: String, default: 'Police Officer' },
  badge: { type: String, required: true },
  department: { type: String, default: 'Bureau of Patrol' },
  subdivision: { type: String, default: '' },
  role: { type: String, enum: ['officer', 'supervisor', 'admin'], default: 'officer' },
  status: { type: String, default: 'Active' },
  bio: { type: String, default: '' },
  email: { type: String, default: '' },
  phone: { type: String, default: '' },
  photo: { type: String, default: '' },
  banner: { type: String, default: '' },
  callsign: { type: String, default: '' },
  certifications: [String],
  commendations: [String],
  infractions: [{
    title: String,
    by: String,
    date: { type: Date, default: Date.now }
  }],
  activityLog: [{
    text: String,
    date: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const newsSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: String, default: 'General' },
  author: { type: String, default: 'Public Affairs' },
  photo: { type: String, default: '' }
}, { timestamps: true });

const wantedSchema = new mongoose.Schema({
  name: { type: String, required: true },
  alias: { type: String, default: '' },
  charges: { type: String, required: true },
  description: { type: String, required: true },
  threat: { type: String, enum: ['High', 'Medium', 'Low'], default: 'Medium' },
  lastSeen: { type: String, default: '' },
  photo: { type: String, default: '' }
}, { timestamps: true });

const districtSchema = new mongoose.Schema({
  num: { type: String, required: true },
  name: { type: String, required: true },
  address: { type: String, required: true },
  phone: { type: String, required: true },
  commander: { type: String, default: '' }
});

const suspectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  age: Number,
  gender: String,
  race: String,
  address: String,
  description: String,
  license: { type: String, default: 'Valid' },
  foid: { type: String, default: 'None' },
  mugshot: { type: String, default: '' },
  status: { type: String, default: 'clear' },
  charges: [{
    code: String,
    title: String,
    reason: String,
    date: { type: Date, default: Date.now }
  }]
}, { timestamps: true });

const applicationSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: String,
  discord: String,
  age: Number,
  rpExperience: String,
  whyJoin: String,
  scenario: String,
  additional: String,
  status: { type: String, default: 'Pending' }
}, { timestamps: true });

const configSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  value: mongoose.Schema.Types.Mixed
});

const logSchema = new mongoose.Schema({
  action: { type: String, required: true },
  details: String,
  userId: String,
  userName: String,
  userRole: String,
  ip: String
}, { timestamps: true });

// ===== MODELS =====
const Officer = mongoose.model('Officer', officerSchema);
const News = mongoose.model('News', newsSchema);
const Wanted = mongoose.model('Wanted', wantedSchema);
const District = mongoose.model('District', districtSchema);
const Suspect = mongoose.model('Suspect', suspectSchema);
const Application = mongoose.model('Application', applicationSchema);
const Config = mongoose.model('Config', configSchema);
const Log = mongoose.model('Log', logSchema);

// ===== LOGGING HELPER =====
async function logAction(req, action, details) {
  try {
    let userName = 'System';
    if (req.userId) {
      const u = await Officer.findById(req.userId).select('firstName lastName');
      if (u) userName = u.firstName + ' ' + u.lastName;
    }
    await Log.create({ action, details, userId: req.userId || '', userName, userRole: req.userRole || '', ip: req.ip });
  } catch(e) { console.error('Log error:', e); }
}

// ===== AUTH MIDDLEWARE =====
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.userRole !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

function supOrAdmin(req, res, next) {
  if (req.userRole !== 'admin' && req.userRole !== 'supervisor') return res.status(403).json({ error: 'Supervisor or admin only' });
  next();
}

// ===== HEALTH CHECK =====
app.get('/', (req, res) => res.json({ status: 'Chicago Police Department API is running', version: '2.0' }));
app.get('/api', (req, res) => res.json({ status: 'ok', endpoints: ['auth', 'officers', 'news', 'wanted', 'districts', 'suspects', 'applications', 'config'] }));

// ===== AUTH ROUTES =====
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const officer = await Officer.findOne({ username: username.toLowerCase() });
    if (!officer) return res.status(401).json({ error: 'Account not found' });
    const valid = await bcrypt.compare(password, officer.password);
    if (!valid) return res.status(401).json({ error: 'Incorrect password' });
    const token = jwt.sign({ id: officer._id, role: officer.role }, JWT_SECRET, { expiresIn: '7d' });
    await Log.create({ action: 'LOGIN', details: officer.firstName + ' ' + officer.lastName + ' logged in', userId: officer._id, userName: officer.firstName + ' ' + officer.lastName, userRole: officer.role });
    res.json({ token, user: { ...officer.toObject(), password: undefined } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const officer = await Officer.findById(req.userId).select('-password');
    if (!officer) return res.status(404).json({ error: 'Not found' });
    res.json(officer);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== OFFICER ROUTES =====
app.get('/api/officers', async (req, res) => {
  try {
    const officers = await Officer.find().select('-password').sort({ rank: 1 });
    res.json(officers);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/officers/:id', async (req, res) => {
  try {
    const officer = await Officer.findById(req.params.id).select('-password');
    if (!officer) return res.status(404).json({ error: 'Not found' });
    res.json(officer);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/officers', auth, adminOnly, async (req, res) => {
  try {
    const { username, password, ...rest } = req.body;
    const exists = await Officer.findOne({ username: username.toLowerCase() });
    if (exists) return res.status(400).json({ error: 'Username taken' });
    const hashed = await bcrypt.hash(password, 10);
    const officer = await Officer.create({ username: username.toLowerCase(), password: hashed, ...rest });
    await logAction(req, 'OFFICER_CREATED', 'Created officer: ' + rest.firstName + ' ' + rest.lastName + ' (Badge #' + rest.badge + ')');
    res.json({ ...officer.toObject(), password: undefined });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/officers/:id', auth, async (req, res) => {
  try {
    const { password, ...updates } = req.body;
    // Officers can only update their own profile (limited fields)
    if (req.userRole === 'officer' && req.userId !== req.params.id) {
      return res.status(403).json({ error: 'Cannot edit other officers' });
    }
    if (password) updates.password = await bcrypt.hash(password, 10);
    const officer = await Officer.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-password');
    await logAction(req, 'OFFICER_UPDATED', 'Updated officer: ' + officer.firstName + ' ' + officer.lastName + (updates.rank ? ' (rank -> ' + updates.rank + ')' : '') + (updates.callsign ? ' (callsign -> ' + updates.callsign + ')' : '') + (updates.subdivision ? ' (subdivision -> ' + updates.subdivision + ')' : '') + (updates.status ? ' (status -> ' + updates.status + ')' : ''));
    res.json(officer);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/officers/:id', auth, adminOnly, async (req, res) => {
  try {
    const toDelete = await Officer.findById(req.params.id);
    await logAction(req, 'OFFICER_REMOVED', 'Removed officer: ' + (toDelete ? toDelete.firstName + ' ' + toDelete.lastName : req.params.id));
    await Officer.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Officer infractions (supervisor/admin)
app.post('/api/officers/:id/infractions', auth, supOrAdmin, async (req, res) => {
  try {
    const officer = await Officer.findById(req.params.id);
    if (!officer) return res.status(404).json({ error: 'Not found' });
    officer.infractions.unshift(req.body);
    await officer.save();
    await logAction(req, 'INFRACTION_ADDED', 'Infraction added to ' + officer.firstName + ' ' + officer.lastName + ': ' + req.body.title);
    res.json(officer.infractions);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Officer activity log
app.post('/api/officers/:id/activity', auth, async (req, res) => {
  try {
    const officer = await Officer.findById(req.params.id);
    if (!officer) return res.status(404).json({ error: 'Not found' });
    officer.activityLog.unshift(req.body);
    await officer.save();
    res.json(officer.activityLog);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== NEWS ROUTES =====
app.get('/api/news', async (req, res) => {
  try {
    const news = await News.find().sort({ createdAt: -1 });
    res.json(news);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/news', auth, adminOnly, async (req, res) => {
  try {
    const item = await News.create(req.body);
    res.json(item);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/news/:id', auth, adminOnly, async (req, res) => {
  try {
    await News.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== WANTED ROUTES =====
app.get('/api/wanted', async (req, res) => {
  try {
    const wanted = await Wanted.find().sort({ createdAt: -1 });
    res.json(wanted);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/wanted', auth, adminOnly, async (req, res) => {
  try {
    const item = await Wanted.create(req.body);
    res.json(item);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/wanted/:id', auth, adminOnly, async (req, res) => {
  try {
    await Wanted.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== DISTRICT ROUTES =====
app.get('/api/districts', async (req, res) => {
  try {
    const districts = await District.find().sort({ num: 1 });
    res.json(districts);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/districts', auth, adminOnly, async (req, res) => {
  try {
    const district = await District.create(req.body);
    res.json(district);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/districts/:id', auth, adminOnly, async (req, res) => {
  try {
    await District.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== SUSPECT ROUTES (MDT) =====
app.get('/api/suspects', auth, async (req, res) => {
  try {
    const { q } = req.query;
    let filter = {};
    if (q) {
      filter = { $or: [
        { name: new RegExp(q, 'i') },
        { description: new RegExp(q, 'i') },
        { address: new RegExp(q, 'i') }
      ]};
    }
    const suspects = await Suspect.find(filter).sort({ createdAt: -1 });
    res.json(suspects);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/suspects', auth, async (req, res) => {
  try {
    const suspect = await Suspect.create(req.body);
    res.json(suspect);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/suspects/:id', auth, async (req, res) => {
  try {
    const suspect = await Suspect.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(suspect);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/suspects/:id', auth, supOrAdmin, async (req, res) => {
  try {
    await Suspect.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/suspects/:id/charges', auth, async (req, res) => {
  try {
    const suspect = await Suspect.findById(req.params.id);
    if (!suspect) return res.status(404).json({ error: 'Not found' });
    suspect.charges.push(req.body);
    await suspect.save();
    res.json(suspect);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/suspects/:id/charges/:idx', auth, supOrAdmin, async (req, res) => {
  try {
    const suspect = await Suspect.findById(req.params.id);
    if (!suspect) return res.status(404).json({ error: 'Not found' });
    suspect.charges.splice(parseInt(req.params.idx), 1);
    await suspect.save();
    res.json(suspect);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== APPLICATION ROUTES =====
app.get('/api/applications', auth, adminOnly, async (req, res) => {
  try {
    const apps = await Application.find().sort({ createdAt: -1 });
    res.json(apps);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/applications', async (req, res) => {
  try {
    const app2 = await Application.create(req.body);
    res.json(app2);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/applications/:id', auth, adminOnly, async (req, res) => {
  try {
    const app2 = await Application.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(app2);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== CONFIG ROUTES =====
app.get('/api/config', async (req, res) => {
  try {
    const configs = await Config.find();
    const obj = {};
    configs.forEach(c => { obj[c.key] = c.value; });
    res.json(obj);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/config/:key', async (req, res) => {
  try {
    const config = await Config.findOne({ key: req.params.key });
    res.json(config ? config.value : null);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/config/:key', auth, adminOnly, async (req, res) => {
  try {
    const config = await Config.findOneAndUpdate(
      { key: req.params.key },
      { key: req.params.key, value: req.body.value },
      { upsert: true, new: true }
    );
    res.json(config);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== AUDIT LOGS =====
app.get('/api/logs', auth, adminOnly, async (req, res) => {
  try {
    const logs = await Log.find().sort({ createdAt: -1 }).limit(200);
    res.json(logs);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== SEED ROUTE (run once to populate initial data) =====
app.post('/api/seed', async (req, res) => {
  try {
    // Check if already seeded
    const count = await Officer.countDocuments();
    if (count > 0) return res.json({ message: 'Already seeded', officers: count });

    // Seed officers
    const officers = [
      { username: 'bstafford', password: await bcrypt.hash('admin123', 10), firstName: 'B.', lastName: 'Stafford', rank: 'Superintendent', badge: '0001', department: 'Office of the Superintendent', subdivision: '', role: 'admin', callsign: '100', certifications: ['Executive Leadership', 'Crisis Management', 'Use of Force Policy'], commendations: ['Distinguished Service Medal', 'Meritorious Service Award'], bio: 'Superintendent of the Chicago Police Department.', email: 'superintendent@chicagopd.gov', phone: '(312) 555-0001' },
      { username: 'jmartinez', password: await bcrypt.hash('super123', 10), firstName: 'J.', lastName: 'Martinez', rank: 'Deputy Superintendent', badge: '0102', department: 'Bureau of Detectives', subdivision: 'Homicide Division', role: 'supervisor', callsign: '110', certifications: ['Criminal Investigations', 'Forensic Analysis'], commendations: ['Investigator of the Year'], bio: 'Deputy Superintendent overseeing the Bureau of Detectives.', email: 'jmartinez@chicagopd.gov', phone: '(312) 555-0102' },
      { username: 'rwilson', password: await bcrypt.hash('lt123', 10), firstName: 'R.', lastName: 'Wilson', rank: 'Lieutenant', badge: '1247', department: 'Bureau of Patrol - District 1', subdivision: 'Watch 2', role: 'supervisor', callsign: '215', certifications: ['Field Training Officer', 'SWAT Certified'], commendations: ['Bravery Award'], bio: 'Watch Commander for District 1.', email: 'rwilson@chicagopd.gov' },
      { username: 'tchen', password: await bcrypt.hash('sgt123', 10), firstName: 'T.', lastName: 'Chen', rank: 'Sergeant', badge: '2456', department: 'Bureau of Patrol - District 7', subdivision: 'Beat 714', role: 'supervisor', callsign: '315', certifications: ['Field Training Officer'], commendations: ['Department Commendation'], bio: 'Patrol Sergeant.' },
      { username: 'klee', password: await bcrypt.hash('officer123', 10), firstName: 'K.', lastName: 'Lee', rank: 'Police Officer', badge: '5678', department: 'Bureau of Patrol - District 1', subdivision: 'Beat 123', role: 'officer', callsign: '412', certifications: ['Firearms Qualified', 'First Aid/CPR'], bio: 'Patrol officer.', email: 'klee@chicagopd.gov' },
      { username: 'apatel', password: await bcrypt.hash('officer123', 10), firstName: 'A.', lastName: 'Patel', rank: 'Police Officer', badge: '5901', department: 'Bureau of Patrol - District 11', subdivision: 'SWAT', role: 'officer', callsign: '418', certifications: ['Firearms Qualified', 'Traffic Enforcement'], commendations: ['Honorable Mention'] },
    ];
    await Officer.insertMany(officers);

    // Seed news
    await News.insertMany([
      { title: 'CPD DUI Saturation Patrol — 4th (South Chicago) District', content: 'The Chicago Police Department will be conducting a DUI Saturation Patrol in the 4th District to combat impaired driving and improve road safety.', category: 'Operations', author: 'Public Affairs' },
      { title: 'CPD DUI Saturation Patrol — 25th (Lincoln) District', content: 'Officers will conduct targeted enforcement operations to reduce DUI incidents in the Lincoln District area.', category: 'Operations', author: 'Public Affairs' },
      { title: 'Community Engagement Initiative Launch', content: 'The CPD is launching a new community engagement initiative to strengthen relationships between officers and neighborhoods.', category: 'Community', author: 'Community Policing' },
      { title: 'New Officer Training Academy Class Begins', content: 'A new class of recruits has started training at the CPD Academy. We welcome these future officers.', category: 'Training', author: 'Training Division' },
    ]);

    // Seed wanted
    await Wanted.insertMany([
      { name: 'Marcus "Ghost" Rivera', alias: 'Ghost', charges: 'Armed Robbery, Assault with a Deadly Weapon', description: 'Male, 6\'1", 190 lbs, black hair, brown eyes. Tattoo on left forearm.', threat: 'High', lastSeen: 'District 11 - Harrison' },
      { name: 'Janice Kowalski', charges: 'Grand Theft Auto, Evading Police', description: 'Female, 5\'6", 140 lbs, blonde hair, blue eyes.', threat: 'Medium', lastSeen: 'District 1 - Central' },
      { name: 'DeShawn Carter', alias: 'Smoke', charges: 'Drug Trafficking, Illegal Firearms', description: 'Male, 5\'10", 175 lbs, black hair, brown eyes. Scar above right eye.', threat: 'High', lastSeen: 'District 7 - Englewood' },
    ]);

    // Seed districts
    await District.insertMany([
      { num: '001', name: 'Central', address: '1718 S. State St.', phone: '(312) 745-4290' },
      { num: '002', name: 'Wentworth', address: '5101 S. Wentworth Ave.', phone: '(312) 747-8366' },
      { num: '003', name: 'Grand Crossing', address: '7040 S. Cottage Grove Ave.', phone: '(312) 747-8201' },
      { num: '007', name: 'Englewood', address: '1438 W. 63rd St.', phone: '(312) 747-8223' },
      { num: '011', name: 'Harrison', address: '3151 W. Harrison St.', phone: '(312) 746-8386' },
    ]);

    // Seed config
    await Config.insertMany([
      { key: 'site', value: { name: 'CHICAGO POLICE DEPARTMENT', motto: 'We serve and protect.', discord: 'https://discord.gg/7vQEJnaD', super: 'B. Stafford', e911: '9-1-1', non911: '(312) 555-1234' }},
      { key: 'heroCards', value: [
        { title: 'Join CPD', desc: 'Make a difference within your community.', btn: 'Get Started', img: 'https://images.unsplash.com/photo-1589578228447-e1a4e481c6c8?w=800&q=80', action: 'discord', size: 'big' },
        { title: 'Use of Force Policy Reform', desc: 'Policies incorporate public feedback.', btn: 'Learn More', img: 'https://images.unsplash.com/photo-1569982175971-d92b01cf8694?w=800&q=80', action: 'departments', size: 'big' },
        { title: "Superintendent's Briefing", btn: 'Learn About Us', img: 'https://images.unsplash.com/photo-1557804506-669a67965ba0?w=600&q=80', action: 'departments', size: 'sm' },
        { title: 'Help Reduce Violence', btn: 'Watch Videos', img: 'https://images.unsplash.com/photo-1494522358652-f30e61a60313?w=600&q=80', action: 'news', size: 'sm' },
        { title: 'Listen to Our Podcast', btn: 'Listen', img: 'https://images.unsplash.com/photo-1477959858617-67f85cf4f1df?w=600&q=80', action: 'news', size: 'sm' },
      ]},
      { key: 'quickLinks', value: [
        { label: 'Community Engagement Calendar', page: 'departments' },
        { label: 'Bureau of Detectives', page: 'departments' },
        { label: 'Bureau of Internal Affairs', page: 'departments' },
        { label: 'Training Needs Assessment', page: 'departments' },
        { label: 'Public Records Release', page: 'services' },
        { label: 'Community Policing Strategic Plans', page: 'departments' },
      ]},
    ]);

    res.json({ message: 'Database seeded successfully!' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== START =====
app.listen(PORT, () => console.log(`CPD API running on port ${PORT}`));
