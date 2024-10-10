const express = require('express');
const multer = require('multer');
const path = require('path');
const db = require('../config/db'); // Adjust the path to your actual database configuration
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

// Display the blockchain list
router.get('/', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }
    db.query('SELECT * FROM cale_blockchain', (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.render('blockchain', { 
            blockchains: results,
            editing: false,
            blockchainId: '',
            blockchainName: '',
            blockchainImage: ''
        });
    });
});

// Add a new blockchain
router.post('/add', upload.single('blockchainimage'), (req, res) => {
    const { blockchainName } = req.body;
    const blockchainImage = req.file ? req.file.filename : null;

    db.query('INSERT INTO cale_blockchain (blockchain_name, blockchain_image) VALUES (?, ?)', [blockchainName, blockchainImage], (err, result) => {
        if (err) {
            console.error('Database insert error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/blockchain');
    });
});

// Route to display form for editing an existing blockchain
router.get('/edit/:id', (req, res) => {
    const blockchainId = req.params.id;
    db.query('SELECT * FROM cale_blockchain WHERE id = ?', [blockchainId], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (results.length > 0) {
            const blockchain = results[0];
            res.render('blockchainForm', {
                editing: true,
                blockchainId: blockchain.id,
                blockchainName: blockchain.blockchain_name,
                blockchainImage: blockchain.blockchain_image
            });
        } else {
            res.redirect('/blockchain');
        }
    });
});

// Update an existing blockchain
router.post('/edit/:id', upload.single('blockchainimage'), (req, res) => {
    const { id } = req.params;
    const { blockchainName } = req.body;
    const blockchainImage = req.file ? req.file.filename : req.body.existingImage; // Preserve existing image if not replaced

    db.query('UPDATE cale_blockchain SET blockchain_name = ?, blockchain_image = ? WHERE id = ?', [blockchainName, blockchainImage, id], (err, result) => {
        if (err) {
            console.error('Database update error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/blockchain');
    });
});

// Delete a blockchain
router.get('/delete/:id', (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM cale_blockchain WHERE id = ?', [id], (err, result) => {
        if (err) {
            console.error('Database delete error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/blockchain');
    });
});

module.exports = router;
