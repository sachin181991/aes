const { modifiedCaesarDecrypt, keyDecrypt } = require('../utils/keyDecrypt');
const {
  importAesKey,
  importPrivateKey,
  decryptUsingPrivateKey,
  decryptUsingAesKey
} = require('../utils/cryptoUtils');

/**
 * Hybrid Decryption Function
 * Decrypts the IV using RSA-OAEP, then decrypts the data using AES-CBC
 * 
 * @param {object} encObject - Object containing encryptedDataBase64 and encryptedIvBase64
 * @param {string} rawPrivateKey - The RSA private key (will be decrypted first)
 * @param {string} rawAesKey - The AES key (will be decrypted first)
 * @returns {Promise<object>} - The decrypted JavaScript object
 */
async function hybridDecryption(encObject, rawPrivateKey, rawAesKey) {
  try {
    // Algorithm configurations
    const rsaAlgorithm = {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    };
    
    const aesAlgorithm = {
      name: 'AES-CBC'
    };
    
    // Decrypt keys
    const decryptedAesKey = modifiedCaesarDecrypt(rawAesKey);
    const decryptedPrivateKey = keyDecrypt(rawPrivateKey);
    
    // Import keys
    const importedAesKey = await importAesKey(decryptedAesKey);
    const importedPrivateKey = await importPrivateKey(decryptedPrivateKey);
    
    // First decrypt the IV using RSA private key
    const ivArrayBuffer = await decryptUsingPrivateKey(
      rsaAlgorithm,
      importedPrivateKey,
      encObject.encryptedIvBase64
    );
    
    // Set the IV in the AES algorithm
    aesAlgorithm.iv = ivArrayBuffer;
    
    // Decrypt the data using AES key
    const plaintextDataArrayBuffer = await decryptUsingAesKey(
      aesAlgorithm,
      importedAesKey,
      encObject.encryptedDataBase64
    );
    
    // Decode the decrypted data
    const textDecoder = new TextDecoder('utf-8');
    const stringURI = textDecoder.decode(plaintextDataArrayBuffer);
    
    // Decode URI component and parse JSON
    const decodedString = decodeURIComponent(stringURI);
    
    // Try to parse as JSON, if it fails return as string
    try {
      return JSON.parse(decodedString);
    } catch (error) {
      return decodedString;
    }
  } catch (error) {
    throw new Error(`An error occurred during decryption: ${error.message}`);
  }
}

module.exports = {
  hybridDecryption
};

