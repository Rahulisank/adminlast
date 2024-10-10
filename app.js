require('dotenv').config();
const express = require("express");
const http = require('http');
// const chat = require('./chat'); 
const cors = require("cors");
const session = require("express-session");
const socketIo = require('socket.io');
const bodyParser = require("body-parser");
const jwt = require('jsonwebtoken');
const passport = require('passport');  // Add Passport.js
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const path = require("path");
const db = require("./config/db");   

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
// Your existing socketConnection function here 
const PORT = process.env.PORT || 4000;
const port = 1500;
const URL = process.env.URL;
  

// Set up middleware
// Allow all origins (or specify certain origins)

// Set up middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(
  session({
    secret: "bgbsdfgbsdbadfba", // Replace with a secure secret key
    resave: false,
    saveUninitialized: true,
  })
);








// Use environment variables for Google client ID and secret
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

 

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
}); 


// Initialize Passport for authentication
app.use(passport.initialize());
app.use(passport.session());

// Middleware to set the current path
app.use((req, res, next) => {
  res.locals.currentPath = req.path; // Pass the current path to EJS templates
  next();
});

app.use(express.static(path.join(__dirname, "public"))); // Correctly serve static files

app.set("view engine", "ejs"); // Set EJS as the templating engine
// Route to serve the chat page
app.get('/chat', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});
// Routes
 
 

app.use("/", require("./routes/auth")); // Authentication-related routes
app.use("/groups", require("./routes/groups")); // CRUD operations for groups
app.use("/blockchain", require("./routes/blockchain")); // CRUD operations for blockchain
app.use("/categories", require("./routes/category")); // CRUD operations for categories
app.use("/marketplace", require("./routes/marketplace"));
app.use("/api", require("./routes/authApi"));























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
     
        if (typeof senderId === 'object') {
          senderId = senderId.userId; // Adjust this line based on your structure
        }
      
        // Check if receiverId is an object and extract the userId
        if (typeof receiverId === 'object') {
          receiverId = receiverId.userId; // Adjust this line based on your structure
        }
        console.log(receiverId);
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




// Error handling middleware (optional but recommended)
app.use((req, res, next) => {
  res.status(404).send("Page Not Found"); // Handle 404 errors
});

app.use((err, req, res, next) => {
  console.error(err.stack); // Log the error stack
  res.status(500).send("Something went wrongdd"); // Handle other errors
});




// Start the server
app.listen(4000, () => {
  console.log(`Server running at ${URL}:${PORT}`);
});
