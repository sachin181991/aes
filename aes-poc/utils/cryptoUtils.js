const crypto = require('crypto');

/**
 * Import AES Key from raw key string
 * @param {string} rawAesKey - The raw AES key (will be decrypted first)
 * @returns {Buffer} - The AES key buffer
 */
async function importAesKey(rawAesKey) {
  if (!rawAesKey) {
    throw new Error('AES key is required');
  }
  
  // Ensure key is 32 bytes (256 bits) for AES-256
  // If key is shorter, pad it; if longer, truncate it
  const keyBuffer = Buffer.from(rawAesKey, 'utf-8');
  
  if (keyBuffer.length < 32) {
    // Pad with zeros
    const paddedKey = Buffer.alloc(32);
    keyBuffer.copy(paddedKey);
    return paddedKey;
  } else if (keyBuffer.length > 32) {
    // Truncate to 32 bytes
    return keyBuffer.slice(0, 32);
  }
  
  return keyBuffer;
}

/**
 * Import RSA Public Key from PEM format
 * @param {string} rawPublicKey - The raw public key (will be decrypted first)
 * @returns {crypto.KeyObject} - The public key object
 */
async function importPublicKey(rawPublicKey) {
  if (!rawPublicKey) {
    throw new Error('Public key is required');
  }
  
  try {
    // Clean up the key - remove any extra whitespace
    let pemKey = rawPublicKey.trim();
    
    // If it already has PEM headers, use it as is
    if (pemKey.includes('-----BEGIN')) {
      // Ensure proper line breaks (64 characters per line for base64)
      // Node.js crypto can handle multi-line PEM, but let's normalize it
      return crypto.createPublicKey(pemKey);
    }
    
    // If no headers, try to add them
    // Remove any existing newlines and format properly
    const keyContent = pemKey.replace(/\s+/g, '');
    
    // Format as PEM with 64 characters per line
    let formattedKey = '';
    for (let i = 0; i < keyContent.length; i += 64) {
      formattedKey += keyContent.substring(i, i + 64) + '\n';
    }
    
    pemKey = `-----BEGIN PUBLIC KEY-----\n${formattedKey}-----END PUBLIC KEY-----`;
    
    return crypto.createPublicKey(pemKey);
  } catch (error) {
    // Try alternative: maybe it's already a valid key format
    try {
      return crypto.createPublicKey(rawPublicKey);
    } catch (err) {
      throw new Error(`Failed to import public key: ${error.message}`);
    }
  }
}

/**
 * Import RSA Private Key from PEM format
 * @param {string} rawPrivateKey - The raw private key (will be decrypted first)
 * @returns {crypto.KeyObject} - The private key object
 */
async function importPrivateKey(rawPrivateKey) {
  if (!rawPrivateKey) {
    throw new Error('Private key is required');
  }
  
  try {
    // Clean up the key - remove any extra whitespace
    let pemKey = rawPrivateKey.trim();
    
    // If it already has PEM headers, use it as is
    if (pemKey.includes('-----BEGIN')) {
      // Node.js crypto can handle multi-line PEM
      return crypto.createPrivateKey(pemKey);
    }
    
    // If no headers, try to add them
    // Remove any existing newlines and format properly
    const keyContent = pemKey.replace(/\s+/g, '');
    
    // Format as PEM with 64 characters per line
    let formattedKey = '';
    for (let i = 0; i < keyContent.length; i += 64) {
      formattedKey += keyContent.substring(i, i + 64) + '\n';
    }
    
    pemKey = `-----BEGIN PRIVATE KEY-----\n${formattedKey}-----END PRIVATE KEY-----`;
    
    return crypto.createPrivateKey(pemKey);
  } catch (error) {
    // Try alternative: maybe it's already a valid key format
    try {
      return crypto.createPrivateKey(rawPrivateKey);
    } catch (err) {
      throw new Error(`Failed to import private key: ${error.message}`);
    }
  }
}

/**
 * Encrypt data using AES-CBC
 * @param {Object} aesAlgorithm - Algorithm configuration with IV
 * @param {Buffer} aesKey - The AES key buffer
 * @param {string} plaintext - The data to encrypt
 * @returns {Buffer} - Encrypted data as ArrayBuffer-like Buffer
 */
async function encryptUsingAesKey(aesAlgorithm, aesKey, plaintext) {
  try {
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, aesAlgorithm.iv);
    let encrypted = cipher.update(plaintext, 'utf-8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted;
  } catch (error) {
    throw new Error(`AES encryption failed: ${error.message}`);
  }
}

/**
 * Encrypt IV using RSA-OAEP
 * @param {Object} rsaAlgorithm - RSA algorithm configuration
 * @param {crypto.KeyObject} publicKey - The RSA public key
 * @param {Buffer} iv - The IV to encrypt
 * @returns {Buffer} - Encrypted IV as ArrayBuffer-like Buffer
 */
async function encryptUsingPublicKey(rsaAlgorithm, publicKey, iv) {
  try {
    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: rsaAlgorithm.hash
      },
      iv
    );
    return encrypted;
  } catch (error) {
    throw new Error(`RSA encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt IV using RSA-OAEP
 * @param {Object} rsaAlgorithm - RSA algorithm configuration
 * @param {crypto.KeyObject} privateKey - The RSA private key
 * @param {string} encryptedIvBase64 - The encrypted IV in base64
 * @returns {Buffer} - Decrypted IV as ArrayBuffer-like Buffer
 */
async function decryptUsingPrivateKey(rsaAlgorithm, privateKey, encryptedIvBase64) {
  try {
    const encryptedIv = Buffer.from(encryptedIvBase64, 'base64');
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: rsaAlgorithm.hash
      },
      encryptedIv
    );
    return decrypted;
  } catch (error) {
    throw new Error(`RSA decryption failed: ${error.message}`);
  }
}

/**
 * Decrypt data using AES-CBC
 * @param {Object} aesAlgorithm - Algorithm configuration with IV
 * @param {Buffer} aesKey - The AES key buffer
 * @param {string} encryptedDataBase64 - The encrypted data in base64
 * @returns {Buffer} - Decrypted data as ArrayBuffer-like Buffer
 */
async function decryptUsingAesKey(aesAlgorithm, aesKey, encryptedDataBase64) {
  try {
    const encryptedData = Buffer.from(encryptedDataBase64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, aesAlgorithm.iv);
    let decrypted = decipher.update(encryptedData);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
  } catch (error) {
    throw new Error(`AES decryption failed: ${error.message}`);
  }
}

/**
 * Convert Buffer to Base64 string
 * @param {Buffer} buffer - The buffer to convert
 * @returns {string} - Base64 encoded string
 */
function arrayBufferToBase64String(buffer) {
  return buffer.toString('base64');
}

module.exports = {
  importAesKey,
  importPublicKey,
  importPrivateKey,
  encryptUsingAesKey,
  encryptUsingPublicKey,
  decryptUsingPrivateKey,
  decryptUsingAesKey,
  arrayBufferToBase64String
};

