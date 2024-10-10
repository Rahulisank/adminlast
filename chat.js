// server.js

const express = require('express');
const http = require('http');
const mysql = require('mysql2');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(bodyParser.json());

const port = process.env.PORT || 3000;

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'chat_app'
});

db.connect((err) => {
  if (err) throw err;
  console.log('MySQL Connected...');
});

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract the token from "Bearer <token>"
    
    if (!token) return res.status(401).send('Access Denied.');
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.status(403).send('Invalid Token.');
      req.user = user;
      next();
    });
  }
  

// Start the server
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});



  
// Socket.io connection
io.on('connection', (socket) => {
    console.log('New client connected');
  
    // Join room for one-to-one chat (room is user-specific)
    socket.on('join', (userId) => {  
      if (typeof userId === 'object') {
        userId = userId.userId;  
      }
  
      socket.join(userId);
      console.log(`User ${userId} joined their chat room.`);
    });
  
    // Handle sending messages
    socket.on('sendMessage', ({ senderId, receiverId, message }) => {
       console.log(senderId);
        if (typeof senderId === 'object') {
          senderId = senderId.userId; // Adjust this line based on your structure
        }
      
        // Check if receiverId is an object and extract the userId
        if (typeof receiverId === 'object') {
          receiverId = receiverId.userId; // Adjust this line based on your structure
        }
      
        // Insert message into the database
        db.query(
          'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
          [senderId, receiverId, message],
          (err, result) => {
            if (err) {
              socket.emit('error', 'Error sending message');
            } else {
              // Emit the message to the receiver's room
              io.to(receiverId).emit('receiveMessage', { senderId, message });
              console.log(`Message from ${senderId} to ${receiverId}: ${message}`);
            }
          }
        );
      });
      
  
    socket.on('disconnect', () => {
      console.log('Client disconnected');
    });
  });
  

  
  // Get all messages between two users
app.get('/messages/:receiverId', authenticateToken, (req, res) => { 
    const receiver_id = req.params.receiverId;
    const sender_id = req.user.userId;
  
    db.query(
      `SELECT * FROM messages WHERE 
       (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp`,
      [sender_id, receiver_id, receiver_id, sender_id],
      (err, results) => {
        if (err) return res.status(500).send('Error retrieving messages.');
        res.json(results);
      }
    );
  });
  