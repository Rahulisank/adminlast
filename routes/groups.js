    const express = require('express');
    const multer = require('multer');
    const path = require('path');
    const db = require('../config/db');
    const router = express.Router();

    // Set up multer for file uploads
    const storage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, 'public/uploads/');
        },
        filename: function (req, file, cb) {
            cb(null, Date.now() + path.extname(file.originalname));
        }
    });
    const upload = multer({ storage: storage });

    // Display the groups list
    router.get('/', (req, res) => {
        if (!req.session.userId) {
            return res.redirect('/');
        }
        db.query('SELECT * FROM `groups`', (err, results) => {
            if (err) throw err;
            res.render('groups', { 
                groups: results,
                editing: false,   // default to false
                groupId: '',
                groupname: '',
                groupImage: ''
            });
        });
    });

    // Add a new group
    router.post('/add', upload.single('groupimage'), (req, res) => {
        const { groupname } = req.body;
        const groupimage = req.file ? req.file.filename : null;

        db.query('INSERT INTO `groups` (groupname, groupimage) VALUES (?, ?)', [groupname, groupimage], (err, result) => {
            if (err) throw err;
            res.redirect('/groups');
        });
    });

    // Route to display form for editing an existing group
    router.get('/edit/:id', (req, res) => {
        const groupId = req.params.id;
        db.query('SELECT * FROM groups WHERE id = ?', [groupId], (err, results) => {
            if (err) throw err;

            if (results.length > 0) {
                const group = results[0];
                res.render('groupsForm', {
                    editing: true,
                    groupId: group.id,
                    groupname: group.groupname,
                    groupImage: group.groupimage
                });
            } else {
                res.redirect('/groups');
            }
        });
    });




    router.post('/edit/:id', upload.single('groupimage'), (req, res) => {
        const { id } = req.params;
        const { groupname } = req.body;

        // Log request body and file data
        console.log('Request Body:', req.body);
        console.log('Uploaded File:', req.file);

        let groupimage = req.body.existingImage;  // Preserve existing image

        if (req.file) {
            // New image uploaded
            groupimage = req.file.filename;
        }

        console.log('Final Group Image:', groupimage);

        db.query('UPDATE `groups` SET groupname = ?, groupimage = ? WHERE id = ?', [groupname, groupimage, id], (err, result) => {
            if (err) {
                console.error('Error updating group:', err);
                return res.status(500).send('Internal Server Error');
            }
            res.redirect('/groups');
        });
    });


    // Delete a group
    router.get('/delete/:id', (req, res) => {
        const { id } = req.params;

        db.query('DELETE FROM `groups` WHERE id = ?', [id], (err, result) => {
            if (err) throw err;
            res.redirect('/groups');
        });
    });

    module.exports = router;
