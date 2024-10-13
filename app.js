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

// Helper function to generate room ID
const generateRoomId = (user1Id, user2Id) => {
  const sortedIds = [user1Id, user2Id].sort((a, b) => a - b);
  return `room_${sortedIds[0]}_${sortedIds[1]}`;
};

// Socket.io connection
io.on('connection', (socket) => {
  console.log('New client connected');

  // Handle joining a chat room (one-to-one) 
socket.on('join', async ({ user1Id, user2Id }) => {
  try {
    const roomId = generateRoomId(user1Id, user2Id);

    // Check if room exists or create it
    const [rows] = await db.query('SELECT * FROM rooms WHERE room_id = ?', [roomId]);
    if (rows.length === 0) {
      await db.query('INSERT INTO rooms (room_id, user1_id, user2_id) VALUES (?, ?, ?)', [roomId, user1Id, user2Id]);
      console.log(`New room created: ${roomId}`);
    } else {
      console.log(`Rejoining room: ${roomId}`);
    }

    // Join the room
    socket.join(roomId);
    console.log(`User ${user1Id} and User ${user2Id} joined room ${roomId}`);

  } catch (error) {
    console.error('Error in join event:', error);
  }
});


  // Handle sending messages
  socket.on('sendMessage', async ({ senderId, receiverId, message }) => {
    try {
      const roomId = generateRoomId(senderId, receiverId);

      // Insert message into the database
      await db.query(
        'INSERT INTO messages (room_id, sender_id, receiver_id, message) VALUES (?, ?, ?, ?)',
        [roomId, senderId, receiverId, message]
      );

      // Emit the message to the receiver's room
      io.to(roomId).emit('receiveMessage', { senderId, message });
      console.log(`Message from ${senderId} to ${receiverId}: ${message}`);

    } catch (err) {
      console.error('Error sending message:', err);
      socket.emit('error', 'Error sending message');
    }
  });

  // Handle disconnect event
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Fetch messages API
app.get('/messages/:userId', async (req, res) => {
  const user1Id = req.user.userId;  // Assuming you use authentication
  const user2Id = req.params.userId;

  try {
    const roomId = generateRoomId(user1Id, user2Id);
    const [messages] = await db.query(
      'SELECT * FROM messages WHERE room_id = ? ORDER BY timestamp',
      [roomId]
    );
    res.json(messages);
  } catch (error) {
    res.status(500).send('Error retrieving messages');
  }
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
