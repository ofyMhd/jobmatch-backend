const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

const serviceAccount = require('path/to/serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://refined-center-404319.firebaseio.com'
});

const db = admin.firestore();
const firebaseAuth = admin.auth();
const app = express();
const port = 3000;

app.use(bodyParser.json());

// Middleware for Firebase Authentication
const authenticateFirebaseUser = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decodedToken = await firebaseAuth.verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, 'your-secret-key', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    req.user = decoded;
    next();
  });
};

// Middleware for admin-only route
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

// User Registration
app.post(
  '/register',
  [
    body('name').notEmpty(),
    body('email').isEmail(),
    body('phone').isMobilePhone(),
    body('password').isLength({ min: 6 }),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Password confirmation does not match password');
      }
      return true;
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, email, phone, password } = req.body;

      const userRef = await db.collection('Users').add({
        name,
        email,
        phone,
        password,
      });

      res.status(201).json({ message: 'User registered successfully', userId: userRef.id });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }
);

// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const snapshot = await db.collection('Users').where('email', '==', email).get();

    if (snapshot.empty) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const user = snapshot.docs[0].data();
    if (user.password !== password) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const token = jwt.sign({ email, role: user.role }, 'your-secret-key', { expiresIn: '1h' });

    res.status(200).json({ message: 'Login successful', user, token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Forgot Password
app.post('/forgotpassword', async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;

    // Perform validation here if needed
    if (!email || !newPassword || !confirmPassword) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }

    // Check if the user exists in the 'users' collection
    const userSnapshot = await db.collection('Users').where('email', '==', email).get();

    if (userSnapshot.empty) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    // Assuming direct password update logic here
    const userDoc = userSnapshot.docs[0];
    await userDoc.ref.update({ password: newPassword });

    res.status(200).json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Profile
app.get('/profile/:userId', authenticateFirebaseUser, async (req, res) => {
  try {
    const userId = req.params.userId;

    const userDoc = await db.collection('Users').doc(userId).get();

    if (!userDoc.exists) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const userData = userDoc.data();
    res.status(200).json(userData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Joma
app.post('/joma', authenticateFirebaseUser, async (req, res) => {
  try {
    const { userId, programStudi, pengalamanKerja, skills } = req.body;

    const jobHistoryRef = await db.collection('JobHistory').add({
      userId,
      programStudi,
      pengalamanKerja,
      skills,
      timestamp: new Date(),
    });

    const linkJobStreet = `https://www.jobstreet.com/search?programStudi=${programStudi}&pengalamanKerja=${pengalamanKerja}&skills=${skills}`;

    await jobHistoryRef.update({ linkJobStreet });

    res.status(201).json({ message: 'Job history added successfully', jobId: jobHistoryRef.id, linkJobStreet });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// History
app.get('/history/:userId', authenticateFirebaseUser, async (req, res) => {
  try {
    const userId = req.params.userId;

    const historyDocs = await db.collection('JobHistory').where('userId', '==', userId).get();

    const historyData = historyDocs.docs.map((doc) => {
      const data = doc.data();
      delete data.linkJobStreet;
      return data;
    });

    res.status(200).json(historyData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Latest History
app.get('/latesthistory/:userId', authenticateFirebaseUser, async (req, res) => {
  try {
    const userId = req.params.userId;

    const latestHistoryDoc = await db
      .collection('JobHistory')
      .where('userId', '==', userId)
      .orderBy('timestamp', 'desc')
      .limit(1)
      .get();

    if (latestHistoryDoc.empty) {
      res.status(404).json({ error: 'No job history found' });
      return;
    }

    const latestHistoryData = latestHistoryDoc.docs[0].data();
    delete latestHistoryData.linkJobStreet;

    res.status(200).json(latestHistoryData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

