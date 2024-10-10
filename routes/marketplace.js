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

// Display the marketplace list
router.get('/', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }
    db.query('SELECT * FROM marketplace', (err, marketplaceResults) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).send('Internal Server Error');
        }
        
        db.query('SELECT * FROM `groups`', (err, groupResults) => {
            if (err) {
                console.error('Database query error:', err);
                return res.status(500).send('Internal Server Error');
            }
            
            db.query('SELECT * FROM cale_blockchain', (err, blockchainResults) => {
                if (err) {
                    console.error('Database query error:', err);
                    return res.status(500).send('Internal Server Error');
                }
                
                res.render('marketplace', { 
                    items: marketplaceResults,
                    groups: groupResults,
                    blockchains: blockchainResults,
                    editing: false,
                    itemId: '',
                    title: '',
                    description: '',
                    image: '',
                    ownerName: '',
                    priceETH: '',
                    contractAddress: '',
                    tokenId: '',
                    tokenStandard: '',
                    groupId: '',
                    blockchainId: ''
                });
            });
        });
    });
});

// Add a new marketplace item
router.post('/add', upload.single('image'), (req, res) => {
    const { title, description, ownerName, priceETH, contractAddress, tokenId, tokenStandard, groupId, blockchainId } = req.body;
    const image = req.file ? req.file.filename : null;

    db.query('INSERT INTO marketplace (title, description, image, owner_name, price_eth, contract_address, token_id, token_standard, group_id, blockchain_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
    [title, description, image, ownerName, priceETH, contractAddress, tokenId, tokenStandard, groupId, blockchainId], (err, result) => {
        if (err) {
            console.error('Database insert error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/marketplace');
    });
});

// Route to display form for editing an existing marketplace item
router.get('/edit/:id', (req, res) => {
    const itemId = req.params.id;
    db.query('SELECT * FROM marketplace WHERE id = ?', [itemId], (err, marketplaceResults) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).send('Internal Server Error');
        }

        if (marketplaceResults.length > 0) {
            const item = marketplaceResults[0];
            
            db.query('SELECT * FROM `groups`', (err, groupResults) => {
                if (err) {
                    console.error('Database query error:', err);
                    return res.status(500).send('Internal Server Error');
                }

                db.query('SELECT * FROM cale_blockchain', (err, blockchainResults) => {
                    if (err) {
                        console.error('Database query error:', err);
                        return res.status(500).send('Internal Server Error');
                    }
                    
                    res.render('marketplace', {
                        editing: true,
                        itemId: item.id,
                        title: item.title,
                        description: item.description,
                        image: item.image,
                        ownerName: item.owner_name,
                        priceETH: item.price_eth,
                        contractAddress: item.contract_address,
                        tokenId: item.token_id,
                        tokenStandard: item.token_standard,
                        groupId: item.group_id,
                        blockchainId: item.blockchain_id,
                        groups: groupResults,
                        blockchains: blockchainResults
                    });
                });
            });
        } else {
            res.redirect('/marketplace');
        }
    });
});

// Update an existing marketplace item
router.post('/edit/:id', upload.single('image'), (req, res) => {
    const { id } = req.params;
    const { title, description, ownerName, priceETH, contractAddress, tokenId, tokenStandard, groupId, blockchainId } = req.body;

    let image = req.body.existingImage;  // Preserve existing image

    if (req.file) {
        // New image uploaded
        image = req.file.filename;
    }

    db.query('UPDATE marketplace SET title = ?, description = ?, image = ?, owner_name = ?, price_eth = ?, contract_address = ?, token_id = ?, token_standard = ?, group_id = ?, blockchain_id = ? WHERE id = ?', 
    [title, description, image, ownerName, priceETH, contractAddress, tokenId, tokenStandard, groupId, blockchainId, id], (err, result) => {
        if (err) {
            console.error('Database update error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/marketplace');
    });
});

// Delete a marketplace item
router.get('/delete/:id', (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM marketplace WHERE id = ?', [id], (err, result) => {
        if (err) {
            console.error('Database delete error:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/marketplace');
    });
});

module.exports = router;
