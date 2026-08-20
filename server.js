const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 80;
const DATA_FILE = path.join(__dirname, 'users.json');

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
    }
  } catch(e) { console.error('读取数据失败:', e); }
  return { users: [], nextId: 1 };
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

let db = loadData();
if (db.users.length === 0) {
  const hashed = bcrypt.hashSync('admin123', 10);
  db.users.push({
    id: 1,
    username: 'admin',
    password: hashed,
    display_name: '系统管理员',
    role: 'admin',
    department: '信息中心',
    active: 1,
    created_at: new Date().toISOString().replace('T',' ').substring(0,19),
    updated_at: new Date().toISOString().replace('T',' ').substring(0,19)
  });
  db.nextId = 2;
  saveData(db);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 8 * 60 * 60 * 1000, sameSite: 'lax' }
}));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
  next();
}

function findUser(id) {
  return db.users.find(u => u.id === parseInt(id));
}

function publicUser(u) {
  const { password, ...pub } = u;
  return pub;
}

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '请输入用户名和密码' });
  const user = db.users.find(u => u.username === username && u.active === 1);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }
  user.updated_at = new Date().toISOString().replace('T',' ').substring(0,19);
  saveData(db);
  req.session.user = {
    id: user.id, username: user.username, display_name: user.display_name,
    role: user.role, department: user.department
  };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: '登出失败' });
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

app.get('/api/user', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: '未登录' });
  res.json({ user: req.session.user });
});

app.get('/api/users', requireAdmin, (req, res) => {
  const users = db.users.map(publicUser).sort((a,b) => a.id - b.id);
  res.json({ users });
});

app.post('/api/users', requireAdmin, (req, res) => {
  const { username, password, display_name, role, department } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (!['admin','editor','viewer'].includes(role)) return res.status(400).json({ error: '无效的角色' });
  if (db.users.find(u => u.username === username)) return res.status(409).json({ error: '用户名已存在' });
  const now = new Date().toISOString().replace('T',' ').substring(0,19);
  const user = {
    id: db.nextId++, username, password: bcrypt.hashSync(password, 10),
    display_name: display_name || username, role: role || 'viewer',
    department: department || '', active: 1, created_at: now, updated_at: now
  };
  db.users.push(user);
  saveData(db);
  res.json({ success: true, id: user.id });
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  const user = findUser(req.params.id);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const { display_name, role, department, active, password } = req.body;
  if (password) user.password = bcrypt.hashSync(password, 10);
  if (display_name !== undefined) user.display_name = display_name;
  if (role) user.role = role;
  if (department !== undefined) user.department = department;
  if (active !== undefined) user.active = parseInt(active);
  user.updated_at = new Date().toISOString().replace('T',' ').substring(0,19);
  saveData(db);
  res.json({ success: true });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  if (req.session.user.id === id) return res.status(400).json({ error: '不能删除自己' });
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: '用户不存在' });
  db.users.splice(idx, 1);
  saveData(db);
  res.json({ success: true });
});

app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: '服务器内部错误' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`服务已启动: http://0.0.0.0:${PORT}`);
  console.log(`默认管理员: admin / admin123`);
});
