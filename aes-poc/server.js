const express = require('express');
const cors = require('cors');
const { hybridEncryption } = require('./services/encryptionService');
const { hybridDecryption } = require('./services/decryptionService');
const crypto = require('crypto');
// Use test keys for testing (plain, unencrypted keys)
// Switch back to './utils/keys' for production with encrypted keys
const { eAk, enPu, enPr } = require('./utils/testKeys');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Use keys from keys.js (encrypted keys from keys.md)
// These will be decrypted when used
const defaultKeys = {
  publicKey: enPu,
  privateKey: enPr,
  aesKey: eAk
};

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
    const { encryptedData, plaintextData, rawPublicKey, rawAesKey, rawPrivateKey } = req.body;

    console.log('Encrypted data:', encryptedData);
    
    let decryptedPlaintextData = null;
    
    // If encryptedData is provided, decrypt it first (Flutter sends encrypted)
    if (encryptedData && encryptedData.encryptedDataBase64 && encryptedData.encryptedIvBase64) {
      try {
        const privateKey = rawPrivateKey || defaultKeys.privateKey;
        const aesKey = rawAesKey || defaultKeys.aesKey;
        decryptedPlaintextData = await hybridDecryption(encryptedData, privateKey, aesKey);
        console.log('Decrypted plaintext data:', decryptedPlaintextData);
      } catch (decryptError) {
        console.error('Decryption error in encrypt endpoint:', decryptError);
        return res.status(400).json({ 
          error: 'Failed to decrypt incoming data: ' + decryptError.message 
        });
      }
    } else if (plaintextData) {
      console.log('plaintext data:', decryptedPlaintextData);
      // Legacy support: if plaintextData is provided directly, use it
      decryptedPlaintextData = plaintextData;
    } else {
      return res.status(400).json({ 
        error: 'Either encryptedData or plaintextData is required' 
      });
    }
    
    // Use provided keys or default keys
    const publicKey = rawPublicKey || defaultKeys.publicKey;
    const aesKey = rawAesKey || defaultKeys.aesKey;
    
    // Encrypt the data
    const encryptedResult = await hybridEncryption(decryptedPlaintextData, publicKey, aesKey);
    const encryptedDataObj = JSON.parse(encryptedResult);
    
    // Return encrypted response (Flutter will decrypt it)
    res.json({
      success: true,
      encryptedData: encryptedDataObj
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
    
    // Decrypt the incoming encrypted data (Flutter sends encrypted request)
    const decryptedResult = await hybridDecryption(encryptedData, privateKey, aesKey);
    
    // The decrypted result should contain the actual encrypted data to decrypt
    // Parse it if it's a JSON string
    let dataToDecrypt = decryptedResult;
    if (typeof decryptedResult === 'string') {
      try {
        dataToDecrypt = JSON.parse(decryptedResult);
      } catch (e) {
        // If not JSON, use as is
      }
    }
    
    // If the decrypted data is an encrypted object, decrypt it again
    if (dataToDecrypt && 
        dataToDecrypt.encryptedDataBase64 && 
        dataToDecrypt.encryptedIvBase64) {
      const finalDecrypted = await hybridDecryption(dataToDecrypt, privateKey, aesKey);
      
      // Encrypt the response before sending back (Flutter will decrypt it)
      const publicKey = defaultKeys.publicKey;
      const encryptedResponse = await hybridEncryption(finalDecrypted, publicKey, aesKey);
      
      res.json({
        success: true,
        encryptedData: JSON.parse(encryptedResponse)
      });
    } else {
      // If it's already decrypted, encrypt the response
      const publicKey = defaultKeys.publicKey;
      const encryptedResponse = await hybridEncryption(decryptedResult, publicKey, aesKey);
      
      res.json({
        success: true,
        encryptedData: JSON.parse(encryptedResponse)
      });
    }
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

