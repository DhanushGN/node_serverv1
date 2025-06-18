const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Buffer } = require('buffer');

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Use environment variables
const SECRET_KEY = Buffer.from(process.env.SECRET_KEY, 'utf-8'); // 32 bytes
const AUTH_TOKEN = process.env.AUTH_TOKEN;
const IV_LENGTH = 16;
const TIMESTAMP_EXPIRY_MS = 60 * 1000; // 60 seconds

app.use(bodyParser.json());

function decrypt(encrypted) {
    const rawData = Buffer.from(encrypted, 'base64');
    const iv = rawData.slice(0, IV_LENGTH);
    const encryptedText = rawData.slice(IV_LENGTH);
    const decipher = crypto.createDecipheriv('aes-256-cbc', SECRET_KEY, iv);
    let decrypted = decipher.update(encryptedText, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

app.post('/decrypt', (req, res) => {
    const clientAuth = req.headers['authorization'];
    const payload = req.body.payload;

    if (!clientAuth || clientAuth !== `Bearer ${AUTH_TOKEN}`) {
        console.log(`[${new Date().toISOString()}] ❌ Unauthorized request`);
        return res.status(403).json({ error: 'Unauthorized' });
    }

    try {
        const decrypted = decrypt(payload);
        const parsed = JSON.parse(decrypted);

        const timestamp = parsed.timestamp;
        if (!timestamp || Math.abs(Date.now() - timestamp) > TIMESTAMP_EXPIRY_MS) {
            console.log(`[${new Date().toISOString()}] ⚠️ Replay attack blocked`);
            return res.status(400).json({ error: 'Timestamp expired or missing' });
        }

        console.log(`[${new Date().toISOString()}] ✅ Valid request from client`);
        return res.status(200).json({ decrypted: parsed.data });

    } catch (err) {
        console.error(`[${new Date().toISOString()}] ❌ Decryption failed`, err.message);
        return res.status(400).json({ error: 'Bad request' });
    }
});

app.listen(PORT, () => {
    console.log(`🔐 Secure Server running on port ${PORT}`);
});
