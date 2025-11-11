const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// In-memory storage untuk API keys (dalam production, gunakan database)
let apiKeys = new Map();

// Generate API Key
function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

// Endpoint untuk generate API key baru
app.post('/api/generate-key', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ 
            success: false, 
            message: 'Username diperlukan' 
        });
    }

    const apiKey = generateApiKey();
    const timestamp = new Date().toISOString();
    
    apiKeys.set(apiKey, {
        username,
        createdAt: timestamp,
        lastUsed: null
    });

    res.json({
        success: true,
        apiKey: apiKey,
        username: username,
        createdAt: timestamp
    });
});

// Endpoint untuk validasi API key
app.post('/api/validate-key', (req, res) => {
    const { apiKey } = req.body;
    
    if (!apiKey) {
        return res.status(400).json({ 
            success: false, 
            message: 'API Key diperlukan' 
        });
    }

    const keyData = apiKeys.get(apiKey);
    
    if (keyData) {
        // Update last used
        keyData.lastUsed = new Date().toISOString();
        apiKeys.set(apiKey, keyData);
        
        return res.json({
            success: true,
            message: 'API Key valid',
            data: keyData
        });
    } else {
        return res.status(401).json({
            success: false,
            message: 'API Key tidak valid'
        });
    }
});

// Endpoint untuk mendapatkan semua API keys
app.get('/api/keys', (req, res) => {
    const keysArray = Array.from(apiKeys.entries()).map(([key, data]) => ({
        apiKey: key,
        ...data
    }));
    
    res.json({
        success: true,
        count: keysArray.length,
        keys: keysArray
    });
});

// Endpoint untuk delete API key
app.delete('/api/delete-key', (req, res) => {
    const { apiKey } = req.body;
    
    if (!apiKey) {
        return res.status(400).json({ 
            success: false, 
            message: 'API Key diperlukan' 
        });
    }

    if (apiKeys.has(apiKey)) {
        apiKeys.delete(apiKey);
        return res.json({
            success: true,
            message: 'API Key berhasil dihapus'
        });
    } else {
        return res.status(404).json({
            success: false,
            message: 'API Key tidak ditemukan'
        });
    }
});

// Protected endpoint example
app.get('/api/protected-data', (req, res) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
        return res.status(401).json({
            success: false,
            message: 'API Key tidak ditemukan di header'
        });
    }

    const keyData = apiKeys.get(apiKey);
    
    if (keyData) {
        keyData.lastUsed = new Date().toISOString();
        apiKeys.set(apiKey, keyData);
        
        return res.json({
            success: true,
            message: 'Akses diberikan',
            data: {
                message: 'Ini adalah data yang dilindungi',
                user: keyData.username,
                timestamp: new Date().toISOString()
            }
        });
    } else {
        return res.status(401).json({
            success: false,
            message: 'API Key tidak valid'
        });
    }
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});
