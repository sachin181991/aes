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
 * Handles custom PEM headers and decrypts the key content
 * @param {string} encryptedKey - The encrypted RSA key
 * @returns {string} - The decrypted RSA key
 */
function keyDecrypt(encryptedKey) {
  if (!encryptedKey) {
    throw new Error('Encrypted key is required');
  }
  
  let key = encryptedKey;
  let isPublicKey = false;
  let isPrivateKey = false;
  let base64Content = '';
  
  // Extract base64 content and determine key type
  if (key.includes('-----ILNPU WbISPJ RLf-----')) {
    isPublicKey = true;
    const match = key.match(/-----ILNPU WbISPJ RLf-----(.*?)-----LUK WbISPJ RLf-----/s);
    if (match && match[1]) {
      base64Content = match[1].trim();
    }
  } else if (key.includes('-----ILNPU WYPcHaL RLf-----')) {
    isPrivateKey = true;
    const match = key.match(/-----ILNPU WYPcHaL RLf-----(.*?)-----LUK WYPcHaL RLf-----/s);
    if (match && match[1]) {
      base64Content = match[1].trim();
    }
  } else if (key.includes('-----BEGIN') && key.includes('-----END')) {
    const match = key.match(/-----BEGIN[^-]+-----\s*(.*?)\s*-----END[^-]+-----/s);
    if (match && match[1]) {
      base64Content = match[1].trim();
      isPublicKey = key.includes('PUBLIC KEY');
      isPrivateKey = key.includes('PRIVATE KEY');
    }
  } else {
    base64Content = key.trim();
  }
  
  if (!base64Content) {
    throw new Error('No key content found');
  }
  
  // Try multiple decryption approaches to find the correct one
  const cleanBase64 = base64Content.replace(/\s+/g, '');
  let decryptedBase64 = '';
  let found = false;
  
  // Approach 1: Try different shift values on base64 string
  for (let shift = 1; shift <= 20; shift++) {
    try {
      const testDecrypted = decryptBase64ContentWithShift(cleanBase64, shift);
      const testBytes = Buffer.from(testDecrypted, 'base64');
      if (testBytes.length > 0 && testBytes[0] === 0x30) {
        decryptedBase64 = testDecrypted;
        found = true;
        break;
      }
    } catch (e) {
      // Continue to next shift
    }
  }
  
  // Approach 2: If base64 string decryption didn't work, try byte-level decryption
  if (!found) {
    try {
      const encryptedBytes = Buffer.from(cleanBase64, 'base64');
      // Try different byte-level shifts
      for (let shift = 1; shift <= 20; shift++) {
        const decryptedBytes = decryptBytesWithShift(encryptedBytes, shift);
        if (decryptedBytes.length > 0 && decryptedBytes[0] === 0x30) {
          decryptedBase64 = decryptedBytes.toString('base64');
          found = true;
          break;
        }
      }
    } catch (e) {
      // Byte-level decryption failed
    }
  }
  
  // Approach 3: If still not found, try the original method (shift 3)
  if (!found) {
    decryptedBase64 = decryptBase64Content(cleanBase64);
  }
  
  if (!decryptedBase64) {
    throw new Error('Failed to decrypt key content - all decryption methods failed');
  }
  
  // Reconstruct PEM format
  const finalBase64 = decryptedBase64.replace(/\s+/g, '');
  let formattedKey = '';
  for (let i = 0; i < finalBase64.length; i += 64) {
    const end = Math.min(i + 64, finalBase64.length);
    formattedKey += finalBase64.substring(i, end) + '\n';
  }
  
  if (isPublicKey) {
    return `-----BEGIN PUBLIC KEY-----\n${formattedKey}-----END PUBLIC KEY-----`;
  } else if (isPrivateKey) {
    return `-----BEGIN PRIVATE KEY-----\n${formattedKey}-----END PRIVATE KEY-----`;
  } else {
    // Default to public key
    return `-----BEGIN PUBLIC KEY-----\n${formattedKey}-----END PUBLIC KEY-----`;
  }
}

/**
 * Decrypt base64 content using modified Caesar cipher
 * Base64 alphabet: A-Z, a-z, 0-9, +, /, =
 * @param {string} encryptedBase64 - The encrypted base64 string
 * @returns {string} - The decrypted base64 string
 */
function decryptBase64Content(encryptedBase64) {
  return decryptBase64ContentWithShift(encryptedBase64, 3);
}

/**
 * Decrypt base64 content with a specific shift value
 * @param {string} encryptedBase64 - The encrypted base64 string
 * @param {number} shift - The shift value
 * @returns {string} - The decrypted base64 string
 */
function decryptBase64ContentWithShift(encryptedBase64, shift) {
  const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  let decrypted = '';
  
  for (let i = 0; i < encryptedBase64.length; i++) {
    const char = encryptedBase64[i];
    const charIndex = base64Chars.indexOf(char);
    
    if (charIndex >= 0) {
      // Decrypt using cyclic shift within base64 alphabet
      const decryptedIndex = (charIndex - shift + base64Chars.length) % base64Chars.length;
      decrypted += base64Chars[decryptedIndex];
    } else {
      // Whitespace or other characters, keep as is
      decrypted += char;
    }
  }
  
  return decrypted;
}

/**
 * Decrypt bytes with a specific shift value
 * @param {Buffer} encryptedBytes - The encrypted bytes
 * @param {number} shift - The shift value
 * @returns {Buffer} - The decrypted bytes
 */
function decryptBytesWithShift(encryptedBytes, shift) {
  const decrypted = Buffer.alloc(encryptedBytes.length);
  
  for (let i = 0; i < encryptedBytes.length; i++) {
    decrypted[i] = (encryptedBytes[i] - shift + 256) % 256;
  }
  
  return decrypted;
}

module.exports = {
  modifiedCaesarDecrypt,
  keyDecrypt
};
