const express = require('express'); // Express framework ko import kar rahe hain web applications banane ke liye
const bodyParser = require('body-parser'); // Body-parser middleware ko import kar rahe hain taaki JSON request bodies ko parse kar sakein
const fs = require('fs').promises; // Promises-based fs (File System) module ko import kar rahe hain files handle karne ke liye
const path = require('path'); // Path module ko import kar rahe hain file aur directory paths handle karne ke liye
const { v4: uuidv4 } = require('uuid'); // UUID module ka version 4 import kar rahe hain unique IDs generate karne ke liye
const bcrypt = require('bcrypt'); // Bcrypt module ko import kar rahe hain passwords securely hash karne ke liye
const cors = require('cors'); // Cors module ko import kar rahe hain taaki Cross-Origin requests handle ho sakein
const jwt = require('jsonwebtoken'); // JSON Web Token module ko import kar rahe hain authentication ke liye tokens create aur verify karne ke liye

const app = express(); // Express application ka ek instance bana rahe hain
const port = 4040; // Server ke liye port number set kar rahe hain
const JWT_SECRET = 'e37149727d75453727e2bec2dbd4357305fe14f492fa8cd1ff2dfd8c4f2f8f302fb09ebf87f9f0b26f4c70e3c49efdc47a3de040fd1639f7d3a198362451ed84'; 
// Ek secret key define kar rahe hain jo JWT tokens sign karne ke liye use hoti hai

app.use(bodyParser.json()); // Body-parser middleware ko use kar rahe hain taaki incoming requests ko JSON format mein parse kar sakein
app.use(cors({
  origin: 'http://localhost:5173', // Cors ko configure kar rahe hain specific origin ke liye
  credentials: true, // Credentials allow kar rahe hain cross-origin requests mein
}));

const DB_FILE = path.join(__dirname, 'users.json'); // Database file ka path set kar rahe hain jismein user data store hoga

async function readDB() { 
  try {
    const data = await fs.readFile(DB_FILE, 'utf8'); // Users.json file ko read kar rahe hain asynchronously
    return JSON.parse(data); // Data ko JSON format mein parse kar rahe hain
  } catch (error) {
    return {}; // Agar file read nahi hui, toh empty object return kar rahe hain
  }
}

async function writeDB(data) {
  await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2)); // Data ko JSON format mein stringify kar ke users.json file mein save kar rahe hain
}

app.post('/api/signup', async (req, res) => { 
  try {
    const userData = req.body; // Request body se user data le rahe hain
    const db = await readDB(); // Database ko load kar rahe hain

    if (db[userData.email] || Object.values(db).some(user => user.username === userData.username)) { 
      return res.status(400).json({ message: 'User already exists' }); // Check kar rahe hain ki user email ya username pehle se exist karta hai ya nahi
    }

    const hashedPassword = await bcrypt.hash(userData.password, 10); // Password ko bcrypt se securely hash kar rahe hain

    const newUser = {
      id: uuidv4(), // Naya unique ID generate kar rahe hain
      ...userData, // User data ko spread kar rahe hain newUser object mein
      password: hashedPassword // Hashed password ko save kar rahe hain
    };

    db[userData.email] = newUser; // Naye user ko database mein add kar rahe hain
    await writeDB(db); // Updated database ko file mein save kar rahe hain

    const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '1h' }); // JWT token generate kar rahe hain user ID ke saath

    res.status(201).json({ message: 'User created successfully', token, userId: newUser.id }); // Success message ke saath token aur user ID bhej rahe hain
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message }); // Agar server error aata hai toh error message bhej rahe hain
  }
});

app.post('/api/login', async (req, res) => { 
  try {
    const { identifier, password } = req.body; // Request body se identifier (email ya username) aur password le rahe hain
    const db = await readDB(); // Database ko load kar rahe hain

    const user = Object.values(db).find(u => u.email === identifier || u.username === identifier); 
    // Database mein user ko dhoondh rahe hain email ya username se

    if (!user) {
      return res.status(400).json({ message: 'User not found' }); // Agar user nahi mila toh error message bhej rahe hain
    }

    const isPasswordValid = await bcrypt.compare(password, user.password); // Password ko verify kar rahe hain hashed password se

    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' }); // Agar password galat hai toh error message bhej rahe hain
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' }); // JWT token generate kar rahe hain login ke liye

    res.json({ message: 'Login successful', token, userId: user.id }); // Success message ke saath token aur user ID bhej rahe hain
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message }); // Agar server error aata hai toh error message bhej rahe hain
  }
});

// JWT ko verify karne ka middleware
// function authenticateToken(req, res, next) {
//   const authHeader = req.headers['authorization']; // Authorization header se token nikal rahe hain
//   const token = authHeader && authHeader.split(' ')[1]; // Token ko extract kar rahe hain header se

//   if (token == null) return res.sendStatus(401); // Agar token absent hai toh 401 Unauthorized status return kar rahe hain

//   jwt.verify(token, JWT_SECRET, (err, user) => { 
//     if (err) return res.sendStatus(403); // Agar token invalid hai toh 403 Forbidden status return kar rahe hain
//     req.user = user; // Verified user ko request object mein attach kar rahe hain
//     next(); // Agle middleware ya route handler ko call kar rahe hain
//   });
// }

// Ek protected route ka example
// app.get('/api/protected', authenticateToken, (req, res) => {
//   res.json({ message: 'This is a protected route', userId: req.user.userId }); // Agar authentication successful hai toh protected message aur user ID return kar rahe hain
// });

app.listen(port, () => { 
  console.log(`Server running at http://localhost:${port}`); // Server ko specified port par start kar rahe hain aur console mein message print kar rahe hain
});
