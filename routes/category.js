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

// Display the category list
router.get('/', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/');
    }
    db.query('SELECT * FROM categories', (err, results) => {
        if (err) throw err;
        res.render('categories', { 
            categories: results,
            editing: false,
            categoryId: '',
            categoryName: '',
            categoryImage: ''
        });
    });
});

// Add a new category
router.post('/add', upload.single('categoryimage'), (req, res) => {
    const { categoryname } = req.body;
    const categoryimage = req.file ? req.file.filename : null;

    db.query('INSERT INTO categories (categoryname, categoryimage) VALUES (?, ?)', [categoryname, categoryimage], (err, result) => {
        if (err) throw err;
        res.redirect('/categories');
    });
});

// Route to display form for editing an existing category
router.get('/edit/:id', (req, res) => {
    const categoryId = req.params.id;
    db.query('SELECT * FROM categories WHERE id = ?', [categoryId], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            const category = results[0];
            res.render('categoryForm', {
                editing: true,
                categoryId: category.id,
                categoryName: category.categoryname,
                categoryImage: category.categoryimage
            });
        } else {
            res.redirect('/categories');
        }
    });
});

router.post('/edit/:id', upload.single('categoryimage'), (req, res) => {
    const { id } = req.params;
    const { categoryname } = req.body;
    let categoryimage = req.body.existingImage;  // Preserve existing image

    if (req.file) {
        categoryimage = req.file.filename;  // Use new image if provided
    }

    db.query('UPDATE categories SET categoryname = ?, categoryimage = ? WHERE id = ?', [categoryname, categoryimage, id], (err, result) => {
        if (err) throw err;
        res.redirect('/categories'); 
    });
});

// Delete a category
router.get('/delete/:id', (req, res) => {
    const { id } = req.params;

    db.query('DELETE FROM categories WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.redirect('/categories');
    });
});

module.exports = router;
