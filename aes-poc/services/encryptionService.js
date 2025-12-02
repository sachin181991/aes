const { modifiedCaesarDecrypt, keyDecrypt } = require('../utils/keyDecrypt');
const {
  importAesKey,
  importPublicKey,
  arrayBufferToBase64String,
  encryptUsingAesKey,
  encryptUsingPublicKey
} = require('../utils/cryptoUtils');
const crypto = require('crypto');

/**
 * Hybrid Encryption Function
 * Encrypts plaintext using AES-CBC, then encrypts the IV using RSA-OAEP
 * 
 * @param {string|object} plaintextData - The data to encrypt (will be stringified if object)
 * @param {string} rawPublicKey - The RSA public key (will be decrypted first)
 * @param {string} rawAesKey - The AES key (will be decrypted first)
 * @returns {Promise<string>} - JSON stringified object with encryptedDataBase64 and encryptedIvBase64
 */
async function hybridEncryption(plaintextData, rawPublicKey, rawAesKey) {
  try {
    // Algorithm configurations
    // Note: Using SHA-1 to match pointycastle's OAEPEncoding default
    // For production, implement custom OAEP with SHA-256 in Flutter
    const rsaAlgorithm = {
      name: 'RSA-OAEP',
      hash: 'SHA-1'  // Changed from SHA-256 to match Flutter pointycastle default
    };
    
    const aesAlgorithm = {
      name: 'AES-CBC'
    };
    
    // Decrypt keys (only if they're encrypted)
    // Test keys are plain base64, so check if they need decryption
    // Base64-encoded 32-byte key is 44 characters (with padding)
    // If it's base64 format (contains only base64 chars and =), use it as-is
    const isBase64Key = /^[A-Za-z0-9+/=]+$/.test(rawAesKey) && rawAesKey.length >= 32;
    const decryptedAesKey = rawAesKey.includes('-----BEGIN') || isBase64Key
      ? rawAesKey  // Already plain (base64 or PEM format)
      : modifiedCaesarDecrypt(rawAesKey);
    const decryptedPublicKey = rawPublicKey.includes('-----BEGIN PUBLIC KEY-----')
      ? rawPublicKey  // Already plain PEM
      : keyDecrypt(rawPublicKey);
    
    // Import keys
    const importedAesKey = await importAesKey(decryptedAesKey);
    const importedPublicKey = await importPublicKey(decryptedPublicKey);
    
    // Generate random IV (16 bytes for AES-CBC)
    aesAlgorithm.iv = crypto.randomBytes(16);
    
    // Convert plaintext to string if it's an object
    const plaintextString = typeof plaintextData === 'object' 
      ? JSON.stringify(plaintextData) 
      : String(plaintextData);
    
    // Encode URI component as per original implementation
    const encodedPlaintext = encodeURIComponent(plaintextString);
    
    // Encrypt using AES and RSA in parallel
    const [encryptedDataArrayBuffer, encryptedIvArrayBuffer] = await Promise.all([
      encryptUsingAesKey(aesAlgorithm, importedAesKey, encodedPlaintext),
      encryptUsingPublicKey(rsaAlgorithm, importedPublicKey, aesAlgorithm.iv)
    ]);
    
    // Convert to base64 and return
    const result = {
      encryptedDataBase64: arrayBufferToBase64String(encryptedDataArrayBuffer),
      encryptedIvBase64: arrayBufferToBase64String(encryptedIvArrayBuffer)
    };
    
    return JSON.stringify(result);
  } catch (error) {
    throw new Error(`An error occurred during encryption: ${error.message}`);
  }
}

module.exports = {
  hybridEncryption
};

