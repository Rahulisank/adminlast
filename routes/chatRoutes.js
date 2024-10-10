const express = require('express');
const { getAllConversations, getMessages } = require('../chat');
const router = express.Router();

// Get all conversations for a user
router.get('/conversations', async (req, res) => {
    const userId = req.query.userId;
    const conversations = await getAllConversations(userId);
    res.json(conversations);
});

// Get messages for a specific conversation
router.get('/conversations/:conversationId/messages', async (req, res) => {
    const { conversationId } = req.params;
    const messages = await getMessages(conversationId);
    res.json(messages);
});

module.exports = router;
