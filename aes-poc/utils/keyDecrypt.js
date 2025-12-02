/**
 * Key decryption utilities
 * These functions decrypt the encrypted keys before use
 */

/**
 * Modified Caesar Cipher Decryption for AES Key
 * @param {string} encryptedKey - The encrypted AES key
 * @returns {string} - The decrypted AES key
 */
function modifiedCaesarDecrypt(encryptedKey) {
  if (!encryptedKey) {
    throw new Error('Encrypted AES key is required');
  }
  
  // Simple Caesar cipher with shift of 3 (can be customized)
  // This is a placeholder - replace with actual decryption logic
  let decrypted = '';
  const shift = 3;
  
  for (let i = 0; i < encryptedKey.length; i++) {
    const char = encryptedKey[i];
    if (char >= 'a' && char <= 'z') {
      decrypted += String.fromCharCode(((char.charCodeAt(0) - 'a'.charCodeAt(0) - shift + 26) % 26) + 'a'.charCodeAt(0));
    } else if (char >= 'A' && char <= 'Z') {
      decrypted += String.fromCharCode(((char.charCodeAt(0) - 'A'.charCodeAt(0) - shift + 26) % 26) + 'A'.charCodeAt(0));
    } else if (char >= '0' && char <= '9') {
      decrypted += String.fromCharCode(((char.charCodeAt(0) - '0'.charCodeAt(0) - shift + 10) % 10) + '0'.charCodeAt(0));
    } else {
      decrypted += char;
    }
  }
  
  return decrypted;
}

/**
 * Key Decryption for RSA Keys
 * @param {string} encryptedKey - The encrypted RSA key
 * @returns {string} - The decrypted RSA key
 */
function keyDecrypt(encryptedKey) {
  if (!encryptedKey) {
    throw new Error('Encrypted key is required');
  }
  
  // If the key is already in PEM format (has BEGIN/END markers), return as is
  // PEM keys are already in the correct format and don't need decryption
  if (encryptedKey.includes('-----BEGIN') && encryptedKey.includes('-----END')) {
    return encryptedKey;
  }
  
  // Placeholder for actual key decryption logic
  // In production, this should use proper key management
  // For now, assuming the key might be base64 encoded or use similar decryption
  try {
    // Try base64 decode first (only if it's not already PEM format)
    // Check if it looks like base64 (no special characters except base64 chars)
    const base64Pattern = /^[A-Za-z0-9+/=\s]+$/;
    if (base64Pattern.test(encryptedKey.trim())) {
      const decoded = Buffer.from(encryptedKey.trim(), 'base64').toString('utf-8');
      // If decoded result looks like PEM, return it
      if (decoded.includes('-----BEGIN')) {
        return decoded;
      }
      // Otherwise, the original might not be base64, return as is
      return encryptedKey;
    }
    // If not base64 pattern, return as is
    return encryptedKey;
  } catch (error) {
    // If base64 decode fails, return as is (assuming already decrypted or different format)
    return encryptedKey;
  }
}

module.exports = {
  modifiedCaesarDecrypt,
  keyDecrypt
};

