const express = require('express');
const db = require('../config/db');
const bcrypt = require('bcrypt');
const router = express.Router();

// Render login page
router.get('/', (req, res) => {
  res.render('login');
});

// Handle login
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
      return res.render('login', { error: 'Please fill in all fields' });
  }

  // Check if user exists
  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
      if (err) throw err;

      if (results.length === 0) {
          return res.render('login', { error: 'Invalid credentials' });
      }

      const user = results[0];

      // Compare password
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) throw err;

          if (isMatch) {
           
              req.session.userId = user.id;
              res.redirect('/dashboard');
          } else {
              res.render('login', { error: 'Invalid credentials' });
          }
      });
  });
});

// Display dashboard page (ensure user is authenticated)
router.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }

    // Fetch user details for the dashboard
    db.query('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, results) => {
        if (err) throw err;

        const user = results[0];
        res.render('dashboard', { username: user.username });
    });
});

// Handle logout
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
            return res.redirect('/dashboard');
        }
        res.redirect('/');
    });
});

module.exports = router;
