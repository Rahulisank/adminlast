const express = require("express");
const router = express.Router();
const passport = require("passport");
const db = require("../config/db"); // Ensure this path is correct
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const multer = require("multer"); 
const path = require('path');
// Setup email transport using Nodemailer
const transporter = nodemailer.createTransport({
  service: "Gmail", // or another email service provider
  auth: {
    user: "rs707406@gmail.com", // Replace with your email
    pass: "mfoguxfbmnlvgteb", // Replace with your email password
  },
});


// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // Append the file extension
  },
});

const upload = multer({ storage: storage });

// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists










 
 


router.post('/auth/google/callback', (req, res) => {
  const { email, name, googleId } = req.body;

  // Check if email exists
  const existingUserQuery = "SELECT id, name, email FROM login WHERE email = ?";
  
  db.execute(existingUserQuery, [email], (err, existingUser) => {
    if (err) {
      console.error('Database error: ', err);
      return res.status(500).json({ success: false, message: 'An error occurred while processing your request.' });
    }

    if (existingUser.length > 0) {
      // Email exists, respond with user data
      return res.status(200).json({
        success: true,
        message: 'Login successful',
        userId: existingUser[0].id,
        email: existingUser[0].email
      });
    } else {
      // Email does not exist, check if Google ID exists
      const existingGoogleIdQuery = "SELECT id FROM login WHERE google_id = ?";
      
      db.execute(existingGoogleIdQuery, [googleId], (err, googleUser) => {
        if (err) {
          console.error('Database error: ', err);
          return res.status(500).json({ success: false, message: 'An error occurred while processing your request.' });
        }

        if (googleUser.length > 0) {
          // Google ID exists, update the email
          const updateUserQuery = `
            UPDATE login SET email = ? 
            WHERE google_id = ?
          `;
          db.execute(updateUserQuery, [email, googleId], (err, result) => {
            if (err) {
              console.error('Database error: ', err);
              return res.status(500).json({ success: false, message: 'An error occurred while processing your request.' });
            }

            // Respond with updated user data
            return res.status(200).json({
              success: true,
              message: 'Login successful',
              userId: googleUser[0].id,
              email
            });
          });
        } else {
          // Neither email nor Google ID exists, insert new user
          const insertUserQuery = `
            INSERT INTO login (name, email, google_id, email_verified, auth_type) 
            VALUES (?, ?, ?, ?, 'google')
          `;
          db.execute(insertUserQuery, [name, email, googleId, true], (err, result) => {
            if (err) {
              console.error('Database error: ', err);
              return res.status(500).json({ success: false, message: 'An error occurred while processing your request.' });
            }

            // Respond with new user data
            return res.status(201).json({
              success: true,
              message: 'User registered successfully',
              userId: result.insertId,
              email
            });
          });
        }
      });
    }
  });
});





 




// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
// Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists // Check if email exists
router.post("/checkemail", (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json({ success: false, message: "Email is required" });
  }

  const query = "SELECT COUNT(*) AS count FROM login WHERE email = ?";
  db.query(query, [email], (err, results) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Database error" , email:email});
    const emailExists = results[0].count > 0;
    res.json({
      success: true,
      exists: emailExists,
      email: email,
      message: emailExists ? "Email exists" : "Email does not exist",
    });
  });
});

// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up
// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up
// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up
// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up// Sign up
router.post("/signup", (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  // Check if email exists
  const checkEmailQuery = "SELECT COUNT(*) AS count FROM login WHERE email = ?";
  db.query(checkEmailQuery, [email], (err, results) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    if (results[0].count > 0)
      return res
        .status(400)
        .json({ success: false, message: "Email already in use" });

    // Hash password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err)
        return res
          .status(500)
          .json({ success: false, message: "Error hashing password" });

      // Insert new user
      const insertQuery =
        "INSERT INTO login (name, email, password, email_verified, created_at) VALUES (?, ?, ?, ?, ?)";
      const emailVerified = false; // Email not verified initially
      const createdAt = new Date();

      db.query(
        insertQuery,
        [name, email, hashedPassword, emailVerified, createdAt],
        (err, results) => {
          if (err)
            return res
              .status(500)
              .json({ success: false, message: "Database error" });

          // Send verification email
          const token = crypto.randomBytes(20).toString("hex");
          const verificationUrl = `${process.env.URL}:${process.env.PORT}/api/verify-email/${token}`;

          const mailOptions = {
            from: "your-email@gmail.com",
            to: email,
            subject: "Account Verification",
            text: `Please verify your account by clicking the link: ${verificationUrl}`,
          };

          transporter.sendMail(mailOptions, (err, info) => {
            if (err)
              return res
                .status(500)
                .json({ success: false, message: "Error sending email" });

            res.json({
              success: true,
              message:
                "Signup successful, please check your email to verify your account",
            });
          });

          // Store token in the database (implement this part as needed)
        }
      );
    });
  });
});

// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email
// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email
// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email
// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email// Verify email
router.get("/verify-email/:token", (req, res) => {
  const token = req.params.token;

  // Validate token and update user email verification status
  // Implement token validation and update query here

  res.json({ success: true, message: "Email verification successful!" });
});

// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login
// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login
// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login// Login
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "Email and password are required" });
  }

  const query = "SELECT id, email,password FROM login WHERE email = ?";
  db.query(query, [email], (err, results) => {
    if (err)
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    if (results.length === 0)
      return res
        .status(400)
        .json({ success: false, message: "Invalid email or password" });

    const user = results[0];

    // Compare passwords
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err)
        return res
          .status(500)
          .json({ success: false, message: "Error comparing passwords" });
      if (!isMatch)
        return res
          .status(400)
          .json({ success: false, message: "Invalid email or password" });

      // Successful login, return user id
      res.json({ success: true, message: "Login successful", userId: user.id, email: user.email });
    });
  });
});

// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
router.post("/addgroup", upload.single("groupimage"), (req, res) => {
  const { groupname, description,matured, userid } = req.body; // Assuming userid is sent in req.body

  // Check if required fields are provided
  if (!groupname || !description || !matured || !req.file || !userid) {
    return res.status(400).json({
      success: false,
      message: "All fields (groupname, description, groupimage,matured, userid) are required",
    });
  }

  // File path for the uploaded image
  const groupImagePath = `${req.file.filename}`;

  // Insert group details into the database
  const insertQuery =
    "INSERT INTO `groups` (groupname, groupimage, description, matured, userid, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
  const createdAt = new Date();
  const updatedAt = createdAt;

  db.query(
    insertQuery,
    [groupname, groupImagePath, description,matured, userid, createdAt, updatedAt],
    (err, result) => {
      if (err) {
        console.error(err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }
      res.json({
        success: true,
        message: "Group inserted successfully",
        groupId: result.insertId,
      });
    }
  );
});




router.post("/editgroup", upload.single("groupimage"), (req, res) => {
  const { groupId, groupname,matured,description, userid } = req.body;
  const newImage = req.file ? req.file.filename : null; // Check if a new image was uploaded

  // Check if required fields are provided
  if (!groupId || !groupname || !description || !matured || !userid) {
    return res.status(400).json({
      success: false,
      message: "All fields (groupId, groupname,matured, description, userid) are required",
    });
  }

  // Construct SQL query based on whether a new image is provided
  let updateQuery = `UPDATE \`groups\` SET groupname = ?, description = ?, matured = ?, userid = ?, updated_at = ?`;
  let queryParams = [groupname, description,matured, userid, new Date()];

  // If a new image is provided, update the image field
  if (newImage) {
    updateQuery += `, groupimage = ?`;
    queryParams.push(newImage);
  }

  updateQuery += ` WHERE id = ?`;
  queryParams.push(groupId);

  db.query(updateQuery, queryParams, (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }
    res.json({
      success: true,
      message: "Group updated successfully",
    });
  });
});





router.post("/deletegroup", (req, res) => {
  const { groupId } = req.body; // Extract groupId from req.body

  // Validate groupId
  if (!groupId) {
    return res.status(400).json({
      success: false,
      message: "groupId is required",
    });
  }

  // Delete group from database
  const deleteQuery = "DELETE FROM `groups` WHERE id = ?";

  db.query(deleteQuery, [groupId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Group not found" });
    }

    res.json({
      success: true,
      message: "Group deleted successfully",
    });
  });
});











router.post("/singlegroup", (req, res) => {
  // Get base URL from environment variables
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // Extract the group ID and user ID from the request body
  const { id, userid } = req.body;

  // Validate the ID and user ID
  if (!id) {
    return res.status(400).json({ success: false, message: "Group ID is required" });
  }
  // if (!userid) {
  //   return res.status(400).json({ success: false, message: "User ID is required" });
  // }

  // Query to retrieve a single group by its ID and optionally check if the userid matches
  const selectQuery = `
    SELECT g.*, j.joinedon
    FROM \`groups\` g
    LEFT JOIN joined_groups j ON g.id = j.groupid AND j.userid = ?
    WHERE g.id = ?
  `;

  db.query(selectQuery, [userid, id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Check if the group was found
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Group not found" });
    }

    // Assuming results[0] is the group object
    const group = results[0];

    // Update the groupimage field with the full URL
    group.groupimage = group.groupimage ? `${baseUrl}${group.groupimage}` : '';

    // Only include `joinedon` if `userid` is a member of the group
    if (group.joinedon === null) {
      delete group.joinedon;
    }

    res.json({
      success: true,
      group: group,
    });
  });
});







router.post("/mygroups", (req, res) => {
  // Extract user ID from the request body
  const { userid } = req.body;

  // Validate user ID
  if (!userid) {
    return res.status(400).json({ success: false, message: "User ID is required" });
  }

  // Get base URL from environment variables
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // Query to retrieve groups where the user ID matches
  const selectQuery = "SELECT * FROM `groups` WHERE `userid` = ?";

  db.query(selectQuery, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to update the groupimage field with the full URL
    const updatedResults = results.map(group => ({
      ...group,
      groupimage: group.groupimage ? `${baseUrl}${group.groupimage}` : ''
    }));

    res.json({
      success: true,
      groups: updatedResults,
    });
  });
});




router.post("/allgroups", (req, res) => {
  // Get base URL from environment variables
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // Query to retrieve all groups from the database
  const selectQuery = "SELECT * FROM `groups`";

  db.query(selectQuery, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to update the groupimage field with the full URL
    const updatedResults = results.map(group => ({
      ...group,
      groupimage: group.groupimage ? `${baseUrl}${group.groupimage}` : ''
    }));

    res.json({
      success: true,
      groups: updatedResults,
    });
  });
});



// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API
// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API// Insert Group API








router.post("/joinedgroups", (req, res) => {
  const { userid } = req.body;

  // Validate if userid is provided
  if (!userid) {
    return res.status(400).json({
      success: false,
      message: "userid is required",
    });
  }

  // Define the base URL for the group images
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // Query to retrieve all groups joined by a specific user
  const selectQuery = `
    SELECT j.id, j.userid, j.groupid, j.joinedon, g.groupname, g.matured, g.description, g.groupimage , g.members , g.posts 
    FROM joined_groups j
    INNER JOIN \`groups\` g ON j.groupid = g.id
    WHERE j.userid = ?
  `;

  db.query(selectQuery, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to update the groupimage field with the full URL
    const updatedResults = results.map(group => ({
      ...group,
      groupimage: group.groupimage ? `${baseUrl}${group.groupimage}` : ''
    }));

    res.json({
      success: true,
      joinedGroups: updatedResults,
    });
  });
});







router.post("/joingroup", (req, res) => {
  const { userid, groupid } = req.body;
  console.table(req.body);
  // Validate input
  if (!userid || !groupid) {
    return res.status(400).json({
      success: false,
      message: "userid and groupid are required",
    });
  }

  // Current time for joinedon
  const joinedOn = new Date();

  // Insert record into joined_groups table
  const insertQuery = "INSERT INTO `joined_groups` (`userid`, `groupid`, `joinedon`) VALUES (?, ?, ?)";

  db.query(insertQuery, [userid, groupid, joinedOn], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    res.json({
      success: true,
      message: "User joined group successfully",
      joinId: result.insertId,
    });
  });
});

router.post("/leavegroup", (req, res) => {
  const { userid, groupid } = req.body;

  // Validate input
  if (!userid || !groupid) {
    return res.status(400).json({
      success: false,
      message: "userid and groupid are required",
    });
  }

  // Delete record from joined_groups table
  const deleteQuery = "DELETE FROM `joined_groups` WHERE `userid` = ? AND `groupid` = ?";

  db.query(deleteQuery, [userid, groupid], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Record not found" });
    }

    res.json({
      success: true,
      message: "User left group successfully",
    });
  });
});




// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API
// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API
// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API
// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API
// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API
// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API// Insert POSTSS API


 






router.post("/singlepost", (req, res) => {
  // Extract post ID from the request body
  const { id } = req.body;

  // Validate post ID
  if (!id) {
    return res.status(400).json({ success: false, message: "Post ID is required" });
  }

  // Get base URL from environment variables
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // SQL query to retrieve a single post and join with groups to get groupname, groupimage, likes, and dislikes
  const selectQuery = `
    SELECT 
      p.id AS post_id,
      p.groupid,
      p.userid AS post_userid,
      p.title,
      p.description,
      p.image,
      p.tags,
      p.matured,
      p.created_at,
      p.updated_at,
      g.groupname,
      g.groupimage,
      -- Aggregate likes
      COALESCE(GROUP_CONCAT(DISTINCT l.userid), '') AS likedby,
      -- Aggregate dislikes
      COALESCE(GROUP_CONCAT(DISTINCT d.userid), '') AS dislikedby
    FROM posts p
    JOIN \`groups\` g ON p.groupid = g.id
    LEFT JOIN \`like_post\` l ON p.id = l.postid
    LEFT JOIN \`dislike_post\` d ON p.id = d.postid
    WHERE p.id = ?
    GROUP BY p.id, g.groupname, g.groupimage
  `;

  db.query(selectQuery, [id], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Check if post was found
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Post not found" });
    }

    // Map over results to format the response
    const post = results[0];
    const updatedPost = {
      id: post.post_id,
      groupid: post.groupid,
      userid: post.post_userid,
      title: post.title,
      description: post.description,
      image: post.image ? `${baseUrl}${post.image}` : '',
      tags: post.tags,
      matured: post.matured,
      created_at: post.created_at,
      updated_at: post.updated_at,
      groupname: post.groupname,
      groupimage: post.groupimage ? `${baseUrl}${post.groupimage}` : '',
      likedby: post.likedby ? post.likedby.split(',') : [],  // Convert comma-separated string to array
      dislikedby: post.dislikedby ? post.dislikedby.split(',') : []  // Convert comma-separated string to array
    };

    res.json({
      success: true,
      post: updatedPost,
    });
  });
});




router.post("/allpost", (req, res) => {
  // Get base URL from environment variables
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // SQL query to retrieve all posts, join with groups, and get likes and dislikes
  const selectQuery = `
    SELECT 
      p.id AS post_id,
      p.groupid,
      p.userid AS post_userid,
      p.title,
      p.description,
      p.image,
      p.tags,
      p.matured,
      p.created_at,
      p.updated_at,
      g.groupname,
      g.groupimage,
      -- Aggregate likes
      COALESCE(GROUP_CONCAT(DISTINCT l.userid), '') AS likedby,
      -- Aggregate dislikes
      COALESCE(GROUP_CONCAT(DISTINCT d.userid), '') AS dislikedby
    FROM posts p
    JOIN \`groups\` g ON p.groupid = g.id
    LEFT JOIN \`like_post\` l ON p.id = l.postid
    LEFT JOIN \`dislike_post\` d ON p.id = d.postid
    GROUP BY p.id, g.groupname, g.groupimage
  `;

  db.query(selectQuery, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to format the response
    const updatedResults = results.map(post => ({
      id: post.post_id,
      groupid: post.groupid,
      userid: post.post_userid,
      title: post.title,
      description: post.description,
      image: post.image ? `${baseUrl}${post.image}` : '',
      tags: post.tags,
      matured: post.matured,
      created_at: post.created_at,
      updated_at: post.updated_at,
      groupname: post.groupname,
      groupimage: post.groupimage ? `${baseUrl}${post.groupimage}` : '',
      likedby: post.likedby ? post.likedby.split(',') : [],  // Convert comma-separated string to array
      dislikedby: post.dislikedby ? post.dislikedby.split(',') : []  // Convert comma-separated string to array
    }));

    res.json({
      success: true,
      posts: updatedResults,
    });
  });
});




router.post("/addpost", upload.single("image"), (req, res) => {
  const { groupid, userid, title, description, tags, matured } = req.body; 

  // Validate input
  if (!groupid || !userid || !title || !description|| !matured) {
    return res.status(400).json({
      success: false,
      message: "groupid, userid, title, description, and matured fields are required",
    });
  }

  // Image handling
  const image = req.file ? req.file.filename : null;

  // Format tags as a comma-separated string
  // Assuming tags is sent as an array in the request body
  const tagsArray = Array.isArray(tags) ? tags.map(tag => tag.trim()) : [];
  const tagsString = tagsArray.length > 0 ? tagsArray.join(',') : null;

  // Insert query
  const insertQuery = `
    INSERT INTO posts (groupid, userid, title, description, image, tags, matured, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const createdAt = new Date();
  const updatedAt = createdAt;

  db.query(
    insertQuery,
    [groupid, userid, title, description, image, tagsString, matured, createdAt, updatedAt],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Database error" });
      }
      res.json({
        success: true,
        message: "Post added successfully",
        postId: result.insertId,
      });
    }
  );
});





router.post("/updatepost", upload.single("image"), (req, res) => {
  const { id, groupid, userid, title, description, tags, matured } = req.body;

  // Validate input
  if (!id || !groupid || !userid || !title || !description || matured === undefined) {
    return res.status(400).json({
      success: false,
      message: "id, groupid, userid, title, description, and matured fields are required",
    });
  }

  // Image handling
  const image = req.file ? req.file.filename : null;

  // Format tags as a comma-separated string
  const tagsArray = Array.isArray(tags) ? tags.map(tag => tag.trim()) : [];
  const tagsString = tagsArray.length > 0 ? tagsArray.join(',') : null;

  // Update query
  const updateQuery = `
    UPDATE posts 
    SET groupid = ?, userid = ?, title = ?, description = ?, image = IFNULL(?, image), tags = ?, matured = ?, updated_at = ?
    WHERE id = ?
  `;

  const updatedAt = new Date();

  db.query(
    updateQuery,
    [groupid, userid, title, description, image, tagsString, matured, updatedAt, id],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: "Database error" });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: "Post not found" });
      }

      res.json({
        success: true,
        message: "Post updated successfully",
      });
    }
  );
});







router.post("/deletepost", (req, res) => {
  const { id, userid } = req.body;

  // Validate input
  if (!id || !userid) {
    return res.status(400).json({
      success: false,
      message: "id and userid are required",
    });
  }

  // Delete query
  const deleteQuery = "DELETE FROM posts WHERE id = ? AND userid = ?";

  db.query(deleteQuery, [id, userid], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Post not found or you do not have permission to delete this post" });
    }

    res.json({
      success: true,
      message: "Post deleted successfully",
    });
  });
});


router.post("/myposts", (req, res) => {
  // Extract user ID from the request body
  const { userid } = req.body;

  // Validate user ID
  if (!userid) {
    return res.status(400).json({ success: false, message: "User ID is required" });
  }

  // Get base URL from environment variables
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // SQL query to retrieve posts, join with groups, and get likes and dislikes
  const selectQuery = `
    SELECT 
      p.id AS post_id,
      p.groupid,
      p.userid AS post_userid,
      p.title,
      p.description,
      p.image,
      p.tags,
      p.matured,
      p.created_at,
      p.updated_at,
      g.groupname,
      g.groupimage,
      -- Aggregate likes
      COALESCE(GROUP_CONCAT(DISTINCT l.userid), '') AS likedby,
      -- Aggregate dislikes
      COALESCE(GROUP_CONCAT(DISTINCT d.userid), '') AS dislikedby
    FROM posts p
    JOIN \`groups\` g ON p.groupid = g.id
    LEFT JOIN \`like_post\` l ON p.id = l.postid
    LEFT JOIN \`dislike_post\` d ON p.id = d.postid
    WHERE p.userid = ?
    GROUP BY p.id, g.groupname, g.groupimage
  `;

  db.query(selectQuery, [userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to format the response
    const updatedResults = results.map(post => ({
      id: post.post_id,
      groupid: post.groupid,
      userid: post.post_userid,
      title: post.title,
      description: post.description,
      image: post.image ? `${baseUrl}${post.image}` : '',
      tags: post.tags,
      matured: post.matured,
      created_at: post.created_at,
      updated_at: post.updated_at,
      groupname: post.groupname,
      groupimage: post.groupimage ? `${baseUrl}${post.groupimage}` : '',
      likedby: post.likedby ? post.likedby.split(',') : [],  // Convert comma-separated string to array
      dislikedby: post.dislikedby ? post.dislikedby.split(',') : []  // Convert comma-separated string to array
    }));

    res.json({
      success: true,
      posts: updatedResults,
    });
  });
});



router.post("/trendingpost", (req, res) => {
  // Get base URL from environment variables
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/`;

  // SQL query to retrieve a random selection of posts, join with groups, and get likes and dislikes
  const selectQuery = `
    SELECT 
      p.id AS post_id,
      p.groupid,
      p.userid AS post_userid,
      p.title,
      p.description,
      p.image,
      p.tags,
      p.matured,
      p.created_at,
      p.updated_at,
      g.groupname,
      g.groupimage,
      -- Aggregate likes
      COALESCE(GROUP_CONCAT(DISTINCT l.userid), '') AS likedby,
      -- Aggregate dislikes
      COALESCE(GROUP_CONCAT(DISTINCT d.userid), '') AS dislikedby
    FROM posts p
    JOIN \`groups\` g ON p.groupid = g.id
    LEFT JOIN \`like_post\` l ON p.id = l.postid
    LEFT JOIN \`dislike_post\` d ON p.id = d.postid 
    GROUP BY p.id, g.groupname, g.groupimage 
    LIMIT 10
  `;

  db.query(selectQuery, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to format the response
    const updatedResults = results.map(post => ({
      id: post.post_id,
      groupid: post.groupid,
      userid: post.post_userid,
      title: post.title,
      description: post.description,
      image: post.image ? `${baseUrl}${post.image}` : '',
      tags: post.tags,
      matured: post.matured,
      created_at: post.created_at,
      updated_at: post.updated_at,
      groupname: post.groupname,
      groupimage: post.groupimage ? `${baseUrl}${post.groupimage}` : '',
      likedby: post.likedby ? post.likedby.split(',') : [],  // Convert comma-separated string to array
      dislikedby: post.dislikedby ? post.dislikedby.split(',') : []  // Convert comma-separated string to array
    }));

    res.json({
      success: true,
      posts: updatedResults,
    });
  });
});














// Route to like a post
router.post("/likepost", (req, res) => {
  const { userid, postid } = req.body;

  if (!userid || !postid) {
    return res.status(400).json({ success: false, message: "User ID and Post ID are required" });
  }

  // Check if the user has already liked the post
  const checkLikeQuery = `
    SELECT * FROM \`like_post\` 
    WHERE userid = ? AND postid = ?
  `;

  db.query(checkLikeQuery, [userid, postid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (results.length > 0) {
      // If already liked, remove the like
      const deleteLikeQuery = `
        DELETE FROM \`like_post\` 
        WHERE userid = ? AND postid = ?
      `;

      db.query(deleteLikeQuery, [userid, postid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        return res.json({ success: true, message: "Like removed successfully" });
      });
    } else {
      // Remove any existing dislike for the same user and post
      const deleteDislikeQuery = `
        DELETE FROM \`dislike_post\` 
        WHERE userid = ? AND postid = ?
      `;

      db.query(deleteDislikeQuery, [userid, postid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        // Insert new like into the like_post table
        const insertLikeQuery = `
          INSERT INTO \`like_post\` (userid, postid, created_at) 
          VALUES (?,?, NOW())
        `;

        db.query(insertLikeQuery, [userid, postid], (err) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Database error" });
          }

          res.json({ success: true, message: "Post liked successfully" });
        });
      });
    }
  });
});









// Route to dislike a post
router.post("/dislikepost", (req, res) => {
  const { userid, postid } = req.body;

  if (!userid || !postid) {
    return res.status(400).json({ success: false, message: "User ID and Post ID are required" });
  }

  // Check if the user has already disliked the post
  const checkDislikeQuery = `
    SELECT * FROM \`dislike_post\` 
    WHERE userid = ? AND postid = ?
  `;

  db.query(checkDislikeQuery, [userid, postid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (results.length > 0) {
      // If already disliked, remove the dislike
      const deleteDislikeQuery = `
        DELETE FROM \`dislike_post\` 
        WHERE userid = ? AND postid = ?
      `;

      db.query(deleteDislikeQuery, [userid, postid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        return res.json({ success: true, message: "Dislike removed successfully" });
      });
    } else {
      // Remove any existing like for the same user and post
      const deleteLikeQuery = `
        DELETE FROM \`like_post\` 
        WHERE userid = ? AND postid = ?
      `;

      db.query(deleteLikeQuery, [userid, postid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        // Insert new dislike into the dislike_post table
        const insertDislikeQuery = `
          INSERT INTO \`dislike_post\` (userid, postid, created_at) 
          VALUES (?,?, NOW())
        `;

        db.query(insertDislikeQuery, [userid, postid], (err) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Database error" });
          }

          res.json({ success: true, message: "Post disliked successfully" });
        });
      });
    }
  });
});









// Route to add a comment with an optional image
router.post("/addcomment", upload.single('image'), (req, res) => {
  const { userid, postid, comment } = req.body;
  const image = req.image ? req.image.filename : null; // Get filename from uploaded file

  if (!userid || !postid || !comment) {
    return res.status(400).json({ success: false, message: "User ID, Post ID, and Comment are required" });
  }

  // Insert new comment into the post_comments table
  const insertCommentQuery = `
    INSERT INTO \`post_comments\` (userid, postid, comment, image, created_at, updated_at) 
    VALUES (?, ?, ?, ?, NOW(), NOW())
  `;

  db.query(insertCommentQuery, [userid, postid, comment, image], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    } 

    res.json({ success: true, message: "Comment added successfully" });
  });
});





// Route to get comments for a specific post
router.post("/comments", (req, res) => {
  const { postid } = req.body;
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/comments/`;

  if (!postid) {
    return res.status(400).json({ success: false, message: "Post ID is required" });
  }

  // Query to retrieve comments along with user details for the specified post
  const selectCommentsQuery = `
    SELECT 
      pc.id, 
      pc.userid, 
      pc.postid, 
      pc.comment, 
      pc.image, 
      pc.created_at, 
      pc.updated_at,
      l.name AS username,
      l.email
    FROM post_comments pc
    JOIN login l ON pc.userid = l.id
    WHERE pc.postid = ?
  `;

  db.query(selectCommentsQuery, [postid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to update image field with the full URL
    const updatedResults = results.map(comment => ({
      ...comment,
      image: comment.image ? `${baseUrl}${comment.image}` : null
    }));

    res.json({
      success: true,
      comments: updatedResults,
    });
  });
});








// Route to get comments for a specific post
router.post("/singlecomment", (req, res) => {
  const { commentid } = req.body;
  const baseUrl = `${process.env.URL}:${process.env.PORT}/uploads/comments/`;

  if (!commentid) {
    return res.status(400).json({ success: false, message: "Commentid is required" });
  }

  // Query to retrieve comments for the specified post
  const selectCommentsQuery = `
    SELECT id, userid, postid, comment, image, created_at, updated_at 
    FROM \`post_comments\` 
    WHERE id = ?
  `;

  db.query(selectCommentsQuery, [commentid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    // Map over results to update image field with the full URL
    const updatedResults = results.map(comment => ({
      ...comment,
      image: comment.image ? `${baseUrl}${comment.image}` : null
    }));

    res.json({
      success: true,
      comments: updatedResults,
    });
  });
});









// Route to add a reply to a comment
router.post("/add-reply", (req, res) => {
  const { commentid, userid } = req.body;

  // Validate input
  if (!commentid || !userid) {
    return res.status(400).json({ success: false, message: "Comment ID and User ID are required" });
  }

  // SQL query to insert a new reply
  const insertReplyQuery = `
    INSERT INTO comment_reply (commentid, userid, created_at)
    VALUES (?, ?, NOW())
  `;

  // Execute the query
  db.query(insertReplyQuery, [commentid, userid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    res.json({
      success: true,
      message: "Reply added successfully",
      replyId: results.insertId  // Return the ID of the newly inserted reply
    });
  });
});







 








// Route to like a comment
router.post("/like-comment", (req, res) => {
  const { userid, commentid } = req.body;

  if (!userid || !commentid) {
    return res.status(400).json({ success: false, message: "User ID and Comment ID are required" });
  }

  // Check if the user has already liked the comment
  const checkLikeQuery = `
    SELECT * FROM comment_likes 
    WHERE userid = ? AND commentid = ?
  `;

  db.query(checkLikeQuery, [userid, commentid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (results.length > 0) {
      // If already liked, remove the like
      const deleteLikeQuery = `
        DELETE FROM comment_likes 
        WHERE userid = ? AND commentid = ?
      `;

      db.query(deleteLikeQuery, [userid, commentid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        return res.json({ success: true, message: "Like removed successfully" });
      });
    } else {
      // Remove any existing dislike for the same user and comment
      const deleteDislikeQuery = `
        DELETE FROM comment_dislikes 
        WHERE userid = ? AND commentid = ?
      `;

      db.query(deleteDislikeQuery, [userid, commentid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        // Insert new like into the comment_likes table
        const insertLikeQuery = `
          INSERT INTO comment_likes (userid, commentid, created_at) 
          VALUES (?, ?, NOW())
        `;

        db.query(insertLikeQuery, [userid, commentid], (err) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Database error" });
          }

          res.json({ success: true, message: "Comment liked successfully" });
        });
      });
    }
  });
});





// Route to dislike a comment
router.post("/dislike-comment", (req, res) => {
  const { userid, commentid } = req.body;

  if (!userid || !commentid) {
    return res.status(400).json({ success: false, message: "User ID and Comment ID are required" });
  }

  // Check if the user has already disliked the comment
  const checkDislikeQuery = `
    SELECT * FROM comment_dislikes 
    WHERE userid = ? AND commentid = ?
  `;

  db.query(checkDislikeQuery, [userid, commentid], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (results.length > 0) {
      // If already disliked, remove the dislike
      const deleteDislikeQuery = `
        DELETE FROM comment_dislikes 
        WHERE userid = ? AND commentid = ?
      `;

      db.query(deleteDislikeQuery, [userid, commentid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        return res.json({ success: true, message: "Dislike removed successfully" });
      });
    } else {
      // Remove any existing like for the same user and comment
      const deleteLikeQuery = `
        DELETE FROM comment_likes 
        WHERE userid = ? AND commentid = ?
      `;

      db.query(deleteLikeQuery, [userid, commentid], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ success: false, message: "Database error" });
        }

        // Insert new dislike into the comment_dislikes table
        const insertDislikeQuery = `
          INSERT INTO comment_dislikes (userid, commentid, created_at) 
          VALUES (?, ?, NOW())
        `;

        db.query(insertDislikeQuery, [userid, commentid], (err) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: "Database error" });
          }

          res.json({ success: true, message: "Comment disliked successfully" });
        });
      });
    }
  });
});





module.exports = router;
