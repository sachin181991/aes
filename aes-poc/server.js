const express = require('express');
const cors = require('cors');
const { hybridEncryption } = require('./services/encryptionService');
const { hybridDecryption } = require('./services/decryptionService');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Generate default keys for testing (in production, these should be securely stored)
function generateDefaultKeys() {
  // Generate RSA key pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  
  // Generate AES key (32 bytes = 256 bits)
  const aesKey = crypto.randomBytes(32).toString('base64');
  
  return { publicKey, privateKey, aesKey };
}

// Store default keys (in production, use proper key management)
const defaultKeys = generateDefaultKeys();

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Encryption service is running' });
});

// Get default keys endpoint (for testing - remove in production)
app.get('/api/keys', (req, res) => {
  res.json({
    publicKey: defaultKeys.publicKey,
    privateKey: defaultKeys.privateKey,
    aesKey: defaultKeys.aesKey
  });
});

// Encryption endpoint
app.post('/api/encrypt', async (req, res) => {
  try {
    const { plaintextData, rawPublicKey, rawAesKey } = req.body;
    
    if (!plaintextData) {
      return res.status(400).json({ error: 'plaintextData is required' });
    }
    
    // Use provided keys or default keys
    const publicKey = rawPublicKey || defaultKeys.publicKey;
    const aesKey = rawAesKey || defaultKeys.aesKey;
    
    const encryptedResult = await hybridEncryption(plaintextData, publicKey, aesKey);
    
    res.json({
      success: true,
      encryptedData: JSON.parse(encryptedResult)
    });
  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'An error occurred during encryption'
    });
  }
});

// Decryption endpoint
app.post('/api/decrypt', async (req, res) => {
  try {
    const { encryptedData, rawPrivateKey, rawAesKey } = req.body;
    
    if (!encryptedData) {
      return res.status(400).json({ error: 'encryptedData is required' });
    }
    
    if (!encryptedData.encryptedDataBase64 || !encryptedData.encryptedIvBase64) {
      return res.status(400).json({ 
        error: 'encryptedData must contain encryptedDataBase64 and encryptedIvBase64' 
      });
    }
    
    // Use provided keys or default keys
    const privateKey = rawPrivateKey || defaultKeys.privateKey;
    const aesKey = rawAesKey || defaultKeys.aesKey;
    
    const decryptedResult = await hybridDecryption(encryptedData, privateKey, aesKey);
    
    res.json({
      success: true,
      decryptedData: decryptedResult
    });
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'An error occurred during decryption'
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Encryption service running on http://localhost:${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log(`Get keys: http://localhost:${PORT}/api/keys`);
  console.log(`Encrypt: POST http://localhost:${PORT}/api/encrypt`);
  console.log(`Decrypt: POST http://localhost:${PORT}/api/decrypt`);
});

module.exports = app;

