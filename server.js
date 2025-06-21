require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { stringify } = require('csv-stringify/sync');
const app = express();
const port = 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// Debug middleware for task routes
app.use('/tasks', (req, res, next) => {
  console.log(`Task Middleware: ${req.method} ${req.url} - Body:`, req.body, 'Params:', req.params);
  next();
});

const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'root',
  database: process.env.DB_NAME || 'attendance_db',
});

db.connect(err => {
  if (err) throw err;
  console.log("✅ Connected to MySQL");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
// Connect to MySQL with retry logic
function connectToDatabase(attempts = 3) {
  return new Promise((resolve, reject) => {
    let attempt = 0;
    function tryConnect() {
      db.connect(err => {
        if (err) {
          console.error(`Attempt ${attempt + 1} - Error connecting to MySQL:`, err.message);
          if (attempt < attempts - 1) {
            attempt++;
            setTimeout(tryConnect, 2000);
          } else {
            reject(new Error('Failed to connect to MySQL after multiple attempts'));
          }
        } else {
          console.log('Connected to MySQL database');
          resolve();
        }
      });
    }
    tryConnect();
  });
}

// Utility: Promise-based MySQL query
function queryPromise(query, params = []) {
  return new Promise((resolve, reject) => {
    db.query(query, params, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
}

// Validate empId
function validateEmpId(empId) {
  return empId && /^[A-Za-z0-9]+$/.test(empId);
}

// In-memory session store (replace with Redis or database in production)
const sessions = {};

// Middleware to check InCharge role
function requireInCharge(req, res, next) {
  const token = req.headers['x-user-id'];
  const session = sessions[token];
  if (!session || session.role !== 'InCharge') {
    console.error('Access denied: InCharge role required', { token });
    return res.status(403).json({ error: 'Access denied: InCharge role required' });
  }
  req.user = session;
  next();
}

// Middleware to authenticate user
function authenticateUser(req, res, next) {
  const token = req.headers['x-user-id'];
  console.log('Authenticating:', { url: req.url, token, sessions: Object.keys(sessions) });
  const session = sessions[token];
  if (!session) {
    console.error('User not authenticated', { token });
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (session.expires < Date.now()) {
    console.error('Session expired', { token, expires: session.expires });
    delete sessions[token];
    return res.status(401).json({ error: 'Session expired' });
  }
  req.user = session;
  next();
}

// Initialize Database
async function initializeDatabase() {
  try {
    const createEmployeesTableQuery = `
      CREATE TABLE IF NOT EXISTS employees (
        emp_id VARCHAR(20) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        base_salary INT NOT NULL,
        role ENUM('Employee', 'InCharge') DEFAULT 'Employee',
        password VARCHAR(255) NOT NULL
      ) ENGINE=InnoDB
    `;
    await queryPromise(createEmployeesTableQuery);
    console.log('Employees table ready');

    // Migration: Add role column if missing
    const roleColumns = await queryPromise("SHOW COLUMNS FROM employees LIKE 'role'");
    if (roleColumns.length === 0) {
      console.log('Adding role column to employees table');
      await queryPromise("ALTER TABLE employees ADD COLUMN role ENUM('Employee', 'InCharge') DEFAULT 'Employee' AFTER base_salary");
    }

    // Migration: Add password column if missing
    const passwordColumns = await queryPromise("SHOW COLUMNS FROM employees LIKE 'password'");
    if (passwordColumns.length === 0) {
      console.log('Adding password column to employees table');
      await queryPromise("ALTER TABLE employees ADD COLUMN password VARCHAR(255) NOT NULL AFTER role");
    }

    const createAttendanceTableQuery = `
      CREATE TABLE IF NOT EXISTS attendance (
        id INT AUTO_INCREMENT PRIMARY KEY,
        emp_id VARCHAR(20) NOT NULL,
        name VARCHAR(100) NOT NULL,
        date DATE NOT NULL,
        time VARCHAR(50) NOT NULL,
        FOREIGN KEY (emp_id) REFERENCES employees(emp_id)
      ) ENGINE=InnoDB
    `;
    await queryPromise(createAttendanceTableQuery);
    console.log('Attendance table ready');

    const createTasksTableQuery = `
      CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        emp_id VARCHAR(20) NOT NULL,
        title VARCHAR(100) NOT NULL,
        description TEXT NOT NULL,
        due_date DATE NOT NULL,
        status ENUM('Pending', 'Completed') DEFAULT 'Pending',
        progress ENUM('Not Started', 'In Progress', 'Completed') DEFAULT 'Not Started',
        taken ENUM('Not Taken', 'Taken') DEFAULT 'Not Taken',
        created_at DATETIME NOT NULL DEFAULT '1970-01-02 00:00:01',
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (emp_id) REFERENCES employees(emp_id) ON DELETE RESTRICT ON UPDATE CASCADE,
        INDEX idx_emp_id (emp_id),
        INDEX idx_status (status),
        INDEX idx_progress (progress),
        INDEX idx_taken (taken)
      ) ENGINE=InnoDB
    `;
    await queryPromise(createTasksTableQuery);
    console.log('Tasks table ready');

    const createLeavesTableQuery = `
      CREATE TABLE IF NOT EXISTS leaves (
        id INT AUTO_INCREMENT PRIMARY KEY,
        emp_id VARCHAR(20) NOT NULL,
        reason TEXT NOT NULL,
        start_date DATE NOT NULL,
        end_date DATE NOT NULL,
        status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
        created_at DATETIME NOT NULL DEFAULT '1970-01-02 00:00:01',
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (emp_id) REFERENCES employees(emp_id) ON DELETE RESTRICT ON UPDATE CASCADE,
        INDEX idx_emp_id (emp_id),
        INDEX idx_status (status)
      ) ENGINE=InnoDB
    `;
    await queryPromise(createLeavesTableQuery);
    console.log('Leaves table ready');

    // Updated bcrypt hashes for password123 and password456
    const insertEmployeesQuery = `
      INSERT IGNORE INTO employees (emp_id, name, base_salary, role, password) VALUES
      ('V2103168007', 'Ajay', 12000, 'Employee', 'password123'),
      ('V2103168131', 'Ali', 8000, 'InCharge', 'password456')
    `;
    await queryPromise(insertEmployeesQuery);
    console.log('Default employees inserted');
  } catch (err) {
    console.error('Error initializing database:', err.message);
    process.exit(1);
  }
}

// API Endpoints

// POST /login
app.post('/login', async (req, res) => {
  console.log('POST /login called', req.body);
  const { empId, password } = req.body;
  if (!empId || !password) {
    console.error('Missing fields:', { empId, password });
    return res.status(400).json({ error: 'Missing empId or password' });
  }
  if (!validateEmpId(empId)) {
    console.error('Invalid empId:', empId);
    return res.status(400).json({ error: 'Invalid empId' });
  }
  try {
    const results = await queryPromise('SELECT emp_id, name, role, password FROM employees WHERE emp_id = ?', [empId]);
    if (results.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(401).json({ error: 'Invalid empId or password' });
    }
    const employee = results[0];
    const isPasswordValid = await bcrypt.compare(password, employee.password);
    if (!isPasswordValid) {
      console.error('Invalid password for empId:', empId);
      return res.status(401).json({ error: 'Invalid empId or password' });
    }
    const token = crypto.randomBytes(16).toString('hex');
    sessions[token] = {
      emp_id: employee.emp_id,
      role: employee.role,
      expires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    };
    console.log('Login successful:', { empId, token });
    res.json({ token, emp_id: employee.emp_id, role: employee.role });
  } catch (err) {
    console.error('Error during login:', err.message, err.stack);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// GET /user
app.get('/user', authenticateUser, (req, res) => {
  console.log('GET /user called', req.user);
  res.json({ emp_id: req.user.emp_id, role: req.user.role });
});

// GET /test
app.get('/test', async (req, res) => {
  console.log('GET /test called');
  try {
    const results = await queryPromise('SELECT COUNT(*) as count FROM employees');
    res.json({ message: 'Test endpoint working', employeeCount: results[0].count });
  } catch (err) {
    console.error('Error in test endpoint:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /employees
app.get('/employees', authenticateUser, async (req, res) => {
  console.log('GET /employees called');
  try {
    const results = await queryPromise('SELECT emp_id, name, base_salary, role FROM employees');
    res.json(results);
  } catch (err) {
    console.error('Error fetching employees:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// PUT /employees/:empId/password
app.put('/employees/:empId/password', authenticateUser, requireInCharge, async (req, res) => {
  console.log('PUT /employees/:empId/password called', req.params, req.body);
  const { empId } = req.params;
  const { password } = req.body;

  if (!validateEmpId(empId)) {
    console.error('Invalid empId:', empId);
    return res.status(400).json({ error: 'Invalid empId' });
  }
  if (!password || password.length < 6) {
    console.error('Invalid password:', { length: password ? password.length : 'undefined' });
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const empCheck = await queryPromise('SELECT emp_id FROM employees WHERE emp_id = ?', [empId]);
    if (empCheck.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(404).json({ error: 'Employee not found' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await queryPromise('UPDATE employees SET password = ? WHERE emp_id = ?', [hashedPassword, empId]);
    console.log('Password updated for empId:', empId);
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error updating password:', err.message, err.stack);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// POST /attendance
// Note: authenticateUser is commented out for testing; uncomment to re-enable authentication
app.post('/attendance', /* authenticateUser, */ async (req, res) => {
  console.log('POST /attendance called', { body: req.body, headers: req.headers });
  const { empId, name, date, time } = req.body;
  if (!empId || !name || !date || !time) {
    console.error('Missing fields:', { empId, name, date, time });
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!validateEmpId(empId)) {
    console.error('Invalid empId:', empId);
    return res.status(400).json({ error: 'Invalid empId' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    console.error('Invalid date format:', date);
    return res.status(400).json({ error: 'Invalid date format (use YYYY-MM-DD)' });
  }
  if (!/^(IN|OUT) - \d{2}:\d{2}:\d{2}$/.test(time)) {
    console.error('Invalid time format:', time);
    return res.status(400).json({ error: 'Invalid time format (use IN/OUT - HH:MM:SS)' });
  }
  try {
    console.log('Checking employee:', { empId });
    const empCheck = await queryPromise('SELECT emp_id, name FROM employees WHERE emp_id = ?', [empId]);
    if (empCheck.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(404).json({ error: 'Employee not found' });
    }
    if (empCheck[0].name !== name) {
      console.error('Name mismatch:', { provided: name, expected: empCheck[0].name });
      return res.status(400).json({ error: 'Name does not match employee record' });
    }
    console.log('Inserting attendance:', { empId, name, date, time });
    const query = 'INSERT INTO attendance (emp_id, name, date, time) VALUES (?, ?, ?, ?)';
    const result = await queryPromise(query, [empId, name, date, time]);
    console.log('Attendance saved:', { id: result.insertId, empId, date, time });
    res.status(201).json({ id: result.insertId });
  } catch (err) {
    console.error('Error saving attendance:', err.message, err.stack);
    res.status(500).json({ error: `Failed to save attendance: ${err.message}` });
  }
});

// GET /attendance
app.get('/attendance', async (req, res) => {
  console.log('GET /attendance called', req.query);
  const { empId } = req.query;
  try {
    if (empId && !validateEmpId(empId)) {
      console.error('Invalid empId:', empId);
      return res.status(400).json({ error: 'Invalid empId' });
    }
    const empCheck = empId ? await queryPromise('SELECT emp_id FROM employees WHERE emp_id = ?', [empId]) : [];
    if (empId && empCheck.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(404).json({ error: 'Employee not found' });
    }
    const query = empId
      ? 'SELECT id, emp_id, name, date, time FROM attendance WHERE emp_id = ? ORDER BY date DESC, time DESC'
      : 'SELECT id, emp_id, name, date, time FROM attendance ORDER BY date DESC, time DESC';
    const results = await queryPromise(query, empId ? [empId] : []);
    res.json(results);
  } catch (err) {
    console.error('Error fetching attendance:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// GET /attendance/logs/download
app.get('/attendance/logs/download', async (req, res) => {
  console.log('GET /attendance/logs/download called', req.query);
  const { startDate, endDate } = req.query;
  if (!startDate || !endDate) {
    console.error('Missing date parameters:', { startDate, endDate });
    return res.status(400).json({ error: 'Start and end dates are required' });
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(startDate) || !/^\d{4}-\d{2}-\d{2}$/.test(endDate)) {
    console.error('Invalid date format:', { startDate, endDate });
    return res.status(400).json({ error: 'Invalid date format (use YYYY-MM-DD)' });
  }
  if (new Date(endDate) < new Date(startDate)) {
    console.error('End date before start date:', { startDate, endDate });
    return res.status(400).json({ error: 'End date must be after start date' });
  }
  try {
    // Fetch all employees
    const employees = await queryPromise('SELECT emp_id, name FROM employees');
    // Fetch attendance records
    const attendance = await queryPromise(
      'SELECT emp_id, name, date, time FROM attendance WHERE date BETWEEN ? AND ? ORDER BY date, emp_id',
      [startDate, endDate]
    );
    // Fetch approved leaves
    const leaves = await queryPromise(
      'SELECT emp_id, start_date, end_date FROM leaves WHERE status = ? AND start_date <= ? AND end_date >= ?',
      ['Approved', endDate, startDate]
    );

    // Process attendance and leaves
    const records = [];
    const start = new Date(startDate);
    const end = new Date(endDate);
    
    for (let date = new Date(start); date <= end; date.setDate(date.getDate() + 1)) {
      const dateStr = date.toISOString().split('T')[0];
      const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
      const formattedDate = `${date.getDate().toString().padStart(2, '0')}-${(date.getMonth() + 1).toString().padStart(2, '0')}-${date.getFullYear()}`;
      
      for (const emp of employees) {
        let status = 'Absent';
        
        // Check leaves
        const isOnLeave = leaves.some(leave => 
          leave.emp_id === emp.emp_id &&
          new Date(leave.start_date) <= date &&
          new Date(leave.end_date) >= date
        );
        if (isOnLeave) {
          status = 'Leave';
        } else {
          // Check attendance
          const hasIn = attendance.some(a => 
            a.emp_id === emp.emp_id && 
            a.date.toISOString().split('T')[0] === dateStr && 
            a.time.startsWith('IN')
          );
          if (hasIn) {
            status = 'Present';
          }
        }
        
        records.push({
          Name: emp.name,
          Date: `${formattedDate} ${dayName}`,
          Status: status
        });
      }
    }

    // Generate CSV
    const csv = stringify(records, { header: true, columns: ['Name', 'Date', 'Status'] });
    res.header('Content-Type', 'text/csv');
    res.attachment(`attendance_logs_${startDate}_to_${endDate}.csv`);
    res.send(csv);
  } catch (err) {
    console.error('Error generating attendance logs:', err.message, err.stack);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// GET /dashboard
app.get('/dashboard', authenticateUser, async (req, res) => {
  console.log('GET /dashboard called');
  try {
    const totalEmployeesResult = await queryPromise('SELECT COUNT(*) as count FROM employees');
    const totalEmployees = totalEmployeesResult[0].count;
    const today = new Date().toISOString().split('T')[0];
    const presentResult = await queryPromise(
      'SELECT COUNT(DISTINCT emp_id) as count FROM attendance WHERE date = ? AND time LIKE "IN%"',
      [today]
    );
    const presentToday = presentResult[0].count;
    const absentToday = totalEmployees - presentToday;
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6);
    const weeklyAttendanceResult = await queryPromise(
      `SELECT DATE(date) as day, COUNT(DISTINCT emp_id) as count
       FROM attendance
       WHERE date >= ? AND time LIKE "IN%"
       GROUP BY DATE(date)
       ORDER BY DATE(date)`,
      [sevenDaysAgo.toISOString().split('T')[0]]
    );
    const days = [];
    for (let i = 0; i < 7; i++) {
      const date = new Date(sevenDaysAgo);
      date.setDate(sevenDaysAgo.getDate() + i);
      days.push({
        day: date.toLocaleDateString('en-US', { weekday: 'short' }),
        count: 0
      });
    }
    weeklyAttendanceResult.forEach(row => {
      const rowDate = new Date(row.day);
      const dayIndex = Math.floor((rowDate - sevenDaysAgo) / (1000 * 60 * 60 * 24));
      if (dayIndex >= 0 && dayIndex < 7) {
        days[dayIndex].count = row.count;
      }
    });
    const recentAttendanceResult = await queryPromise(
      `SELECT emp_id, name, date, time
       FROM attendance
       ORDER BY date DESC, time DESC
       LIMIT 5`
    );
    const recentAttendance = recentAttendanceResult.map(entry => ({
      employee: entry.name,
      date: entry.date,
      status: entry.time.includes('IN') ? 'Present' : 'Absent',
      checkIn: entry.time.includes('IN') ? entry.time.replace('IN - ', '') : 'N/A',
      checkOut: entry.time.includes('OUT') ? entry.time.replace('OUT - ', '') : 'N/A'
    }));
    res.json({
      totalEmployees,
      presentToday,
      absentToday,
      weeklyAttendance: days,
      recentAttendance
    });
  } catch (err) {
    console.error('Error fetching dashboard data:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// GET /leaves
app.get('/leaves', authenticateUser, async (req, res) => {
  console.log('GET /leaves called', req.query);
  const { empId } = req.query;
  try {
    if (empId && !validateEmpId(empId)) {
      console.error('Invalid empId:', empId);
      return res.status(400).json({ error: 'Invalid empId' });
    }
    const empCheck = empId ? await queryPromise('SELECT emp_id FROM employees WHERE emp_id = ?', [empId]) : [];
    if (empId && empCheck.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(404).json({ error: 'Employee not found' });
    }
    const query = empId
      ? 'SELECT id, emp_id, reason, start_date, end_date, status FROM leaves WHERE emp_id = ?'
      : 'SELECT id, emp_id, reason, start_date, end_date, status FROM leaves';
    const results = await queryPromise(query, empId ? [empId] : []);
    res.json(results.map(r => ({
      id: r.id,
      empId: r.emp_id,
      reason: r.reason,
      startDate: r.start_date,
      endDate: r.end_date,
      status: r.status
    })));
  } catch (err) {
    console.error('Error fetching leaves:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// POST /leaves
app.post('/leaves', authenticateUser, async (req, res) => {
  console.log('POST /leaves called', req.body);
  const { empId, reason, startDate, endDate } = req.body;
  if (!empId || !reason || !startDate || !endDate) {
    console.error('Missing fields:', req.body);
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!validateEmpId(empId)) {
    console.error('Invalid empId:', empId);
    return res.status(400).json({ error: 'Invalid empId' });
  }
  try {
    const empCheck = await queryPromise('SELECT emp_id FROM employees WHERE emp_id = ?', [empId]);
    if (empCheck.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(404).json({ error: 'Employee not found' });
    }
    const formattedStartDate = new Date(startDate).toISOString().split('T')[0];
    const formattedEndDate = new Date(endDate).toISOString().split('T')[0];
    if (new Date(formattedEndDate) < new Date(formattedStartDate)) {
      console.error('End date before start date');
      return res.status(400).json({ error: 'End date must be after start date' });
    }
    const query = 'INSERT INTO leaves (emp_id, reason, start_date, end_date, status) VALUES (?, ?, ?, ?, ?)';
    const result = await queryPromise(query, [empId, reason, formattedStartDate, formattedEndDate, 'Pending']);
    const leave = { id: result.insertId, empId, reason, startDate: formattedStartDate, endDate: formattedEndDate, status: 'Pending' };
    res.status(201).json(leave);
  } catch (err) {
    console.error('Error creating leave:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// PUT /leaves/:id
app.put('/leaves/:id', requireInCharge, async (req, res) => {
  console.log('PUT /leaves/:id called', req.params, req.body);
  const { id } = req.params;
  const { status } = req.body;
  if (!['Pending', 'Approved', 'Rejected'].includes(status)) {
    console.error('Invalid status:', status);
    return res.status(400).json({ error: 'Invalid status' });
  }
  try {
    const check = await queryPromise('SELECT id FROM leaves WHERE id = ?', [id]);
    if (check.length === 0) {
      console.error('Leave not found:', id);
      return res.status(404).json({ error: 'Leave not found' });
    }
    const query = 'UPDATE leaves SET status = ? WHERE id = ?';
    await queryPromise(query, [status, id]);
    res.json({ id, status });
  } catch (err) {
    console.error('Error updating leave:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// GET /leaves/pending/count
app.get('/leaves/pending/count', authenticateUser, async (req, res) => {
  console.log('GET /leaves/pending/count called');
  try {
    const result = await queryPromise('SELECT COUNT(*) as count FROM leaves WHERE status = ?', ['Pending']);
    res.json({ count: result[0].count });
  } catch (err) {
    console.error('Error fetching pending leave count:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// GET /tasks
app.get('/tasks', authenticateUser, async (req, res) => {
  console.log('GET /tasks called', req.query);
  const { empId } = req.query;
  try {
    if (empId && !validateEmpId(empId)) {
      console.error('Invalid empId:', empId);
      return res.status(400).json({ error: 'Invalid empId' });
    }
    const empCheck = empId ? await queryPromise('SELECT emp_id FROM employees WHERE emp_id = ?', [empId]) : [];
    if (empId && empCheck.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(404).json({ error: 'Employee not found' });
    }
    const query = empId
      ? 'SELECT id, emp_id, title, description, due_date, status, progress, taken FROM tasks WHERE emp_id = ?'
      : 'SELECT id, emp_id, title, description, due_date, status, progress, taken FROM tasks';
    const results = await queryPromise(query, empId ? [empId] : []);
    res.json(results.map(r => ({
      id: r.id,
      empId: r.emp_id,
      title: r.title,
      description: r.description,
      dueDate: r.due_date,
      status: r.status,
      progress: r.progress,
      taken: r.taken
    })));
  } catch (err) {
    console.error('Error fetching tasks:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// POST /tasks
app.post('/tasks', requireInCharge, async (req, res) => {
  console.log('POST /tasks called', req.body);
  const { empId, title, description, dueDate } = req.body;
  if (!empId || !title || !description || !dueDate) {
    console.error('Missing fields:', req.body);
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!validateEmpId(empId)) {
    console.error('Invalid empId:', empId);
    return res.status(400).json({ error: 'Invalid empId' });
  }
  try {
    const empCheck = await queryPromise('SELECT emp_id, role FROM employees WHERE emp_id = ?', [empId]);
    if (empCheck.length === 0) {
      console.error('Employee not found:', empId);
      return res.status(404).json({ error: 'Employee not found' });
    }
    if (empCheck[0].role !== 'Employee') {
      console.error('Tasks can only be assigned to Employees:', empId);
      return res.status(400).json({ error: 'Tasks can only be assigned to Employees' });
    }
    const formattedDueDate = new Date(dueDate).toISOString().split('T')[0];
    const query = 'INSERT INTO tasks (emp_id, title, description, due_date, status, progress, taken) VALUES (?, ?, ?, ?, ?, ?, ?)';
    const result = await queryPromise(query, [empId, title, description, formattedDueDate, 'Pending', 'Not Started', 'Not Taken']);
    const task = { id: result.insertId, empId, title, description, dueDate: formattedDueDate, status: 'Pending', progress: 'Not Started', taken: 'Not Taken' };
    res.status(201).json(task);
  } catch (err) {
    console.error('Error creating task:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// POST /tasks/:id/accept
app.post('/tasks/:id/accept', authenticateUser, async (req, res) => {
  console.log('POST /tasks/:id/accept called', req.params, req.body);
  const { id } = req.params;
  const { empId } = req.body;
  if (!empId || !validateEmpId(empId)) {
    console.error('Invalid or missing empId:', empId);
    return res.status(400).json({ error: 'Invalid or missing empId' });
  }
  try {
    const taskCheck = await queryPromise('SELECT emp_id, taken FROM tasks WHERE id = ?', [id]);
    if (taskCheck.length === 0) {
      console.error('Task not found:', id);
      return res.status(404).json({ error: 'Task not found' });
    }
    if (taskCheck[0].emp_id !== empId) {
      console.error('Task not assigned to this employee:', { taskEmpId: taskCheck[0].emp_id, empId });
      return res.status(403).json({ error: 'Task not assigned to this employee' });
    }
    if (taskCheck[0].taken === 'Taken') {
      console.error('Task already taken:', id);
      return res.status(400).json({ error: 'Task already taken' });
    }
    const query = 'UPDATE tasks SET taken = ? WHERE id = ?';
    await queryPromise(query, ['Taken', id]);
    res.json({ id, taken: 'Taken' });
  } catch (err) {
    console.error('Error accepting task:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// PUT /tasks/:id/progress
app.put('/tasks/:id/progress', authenticateUser, async (req, res) => {
  console.log('PUT /tasks/:id/progress called', req.params, req.body);
  const { id } = req.params;
  const { progress, empId } = req.body;
  if (!['Not Started', 'In Progress', 'Completed'].includes(progress)) {
    console.error('Invalid progress:', progress);
    return res.status(400).json({ error: 'Invalid progress status' });
  }
  if (!empId || !validateEmpId(empId)) {
    console.error('Invalid or missing empId:', empId);
    return res.status(400).json({ error: 'Invalid or missing empId' });
  }
  try {
    const taskCheck = await queryPromise('SELECT emp_id, taken FROM tasks WHERE id = ?', [id]);
    if (taskCheck.length === 0) {
      console.error('Task not found:', id);
      return res.status(404).json({ error: 'Task not found' });
    }
    if (taskCheck[0].emp_id !== empId) {
      console.error('Task not assigned to this employee:', { taskEmpId: taskCheck[0].emp_id, empId });
      return res.status(403).json({ error: 'Task not assigned to this employee' });
    }
    if (taskCheck[0].taken !== 'Taken') {
      console.error('Task not accepted:', id);
      return res.status(400).json({ error: 'Task must be accepted before updating progress' });
    }
    const status = progress === 'Completed' ? 'Completed' : 'Pending';
    const query = 'UPDATE tasks SET progress = ?, status = ? WHERE id = ?';
    await queryPromise(query, [progress, status, id]);
    res.json({ id, progress, status });
  } catch (err) {
    console.error('Error updating task progress:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// GET /analytics/tasks
app.get('/analytics/tasks', authenticateUser, async (req, res) => {
  console.log('GET /analytics/tasks called');
  try {
    const query = `
      SELECT e.emp_id, e.name,
        SUM(CASE WHEN t.progress = 'Not Started' THEN 1 ELSE 0 END) as notStarted,
        SUM(CASE WHEN t.progress = 'In Progress' THEN 1 ELSE 0 END) as inProgress,
        SUM(CASE WHEN t.progress = 'Completed' THEN 1 ELSE 0 END) as completed
      FROM employees e
      LEFT JOIN tasks t ON e.emp_id = t.emp_id
      WHERE e.role = 'Employee'
      GROUP BY e.emp_id, e.name
      HAVING notStarted > 0 OR inProgress > 0 OR completed > 0
    `;
    const results = await queryPromise(query);
    res.json(results.map(r => ({
      empId: r.emp_id,
      name: r.name,
      notStarted: parseInt(r.notStarted, 10),
      inProgress: parseInt(r.inProgress, 10),
      completed: parseInt(r.completed, 10)
    })));
  } catch (err) {
    console.error('Error fetching task analytics:', err.message);
    res.status(500).json({ error: `Database error: ${err.message}` });
  }
});

// POST /logout
app.post('/logout', (req, res) => {
  console.log('POST /logout called');
  const token = req.headers['x-user-id'];
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.json({ message: 'Logged out successfully' });
});

// Serve static files
app.use(express.static('public'));

// Start Server
async function startServer() {
  try {
    await connectToDatabase();
    await initializeDatabase();
    app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err.message);
    process.exit(1);
  }
}

startServer();