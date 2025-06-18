const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = "ThisIsASecretKeyForAES256!!!"; // 32 bytes
const IV_LENGTH = 16;

function decrypt(encryptedBase64) {
    const encrypted = Buffer.from(encryptedBase64, 'base64');
    const iv = encrypted.slice(0, IV_LENGTH);
    const content = encrypted.slice(IV_LENGTH);

    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(SECRET_KEY), iv);
    let decrypted = decipher.update(content);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString();
}

app.post('/decrypt', (req, res) => {
    try {
        const encrypted = req.body.payload;
        const message = decrypt(encrypted);
        console.log("Decrypted:", message);
        res.json({ decrypted: message });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: "Decryption failed" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
