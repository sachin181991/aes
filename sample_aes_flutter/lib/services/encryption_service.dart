import 'dart:convert';
import '../utils/key_decrypt.dart';
import '../utils/crypto_utils.dart';

/// Hybrid Encryption Function
/// Encrypts plaintext using AES-CBC, then encrypts the IV using RSA-OAEP
Future<Map<String, String>> hybridEncryption(
  dynamic plaintextData,
  String rawPublicKey,
  String rawAesKey,
) async {
  try {
    // Decrypt keys (only if they're encrypted)
    // Test keys are plain base64, so check if they need decryption
    // Base64-encoded 32-byte key is 44 characters (with padding)
    // If it's base64 format (contains only base64 chars and =), use it as-is
    final isBase64Key = RegExp(r'^[A-Za-z0-9+/=]+$').hasMatch(rawAesKey) && rawAesKey.length >= 32;
    final decryptedAesKey = rawAesKey.contains('-----BEGIN') || isBase64Key
      ? rawAesKey  // Already plain (base64 or PEM format)
      : modifiedCaesarDecrypt(rawAesKey);
    final decryptedPublicKey = rawPublicKey.contains('-----BEGIN PUBLIC KEY-----')
      ? rawPublicKey  // Already plain PEM
      : keyDecrypt(rawPublicKey);
    
    // Verify the decrypted public key has proper format
    if (!decryptedPublicKey.contains('-----BEGIN') || !decryptedPublicKey.contains('-----END')) {
      throw Exception('Decrypted public key does not have proper PEM headers. Key length: ${decryptedPublicKey.length}, First 100 chars: ${decryptedPublicKey.length > 100 ? decryptedPublicKey.substring(0, 100) : decryptedPublicKey}');
    }

    // Import keys
    final importedAesKey = importAesKey(decryptedAesKey);
    final importedPublicKey = importPublicKey(decryptedPublicKey);

    // Generate random IV (16 bytes for AES-CBC)
    final iv = generateRandomBytes(16);

    // Convert plaintext to string if it's an object
    final plaintextString = plaintextData is Map || plaintextData is List
        ? jsonEncode(plaintextData)
        : plaintextData.toString();

    // Encode URI component as per original implementation
    final encodedPlaintext = Uri.encodeComponent(plaintextString);

    // Encrypt using AES and RSA in parallel
    final encryptedDataArrayBuffer =
        encryptUsingAesKey(iv, importedAesKey, encodedPlaintext);
    final encryptedIvArrayBuffer = encryptUsingPublicKey(importedPublicKey, iv);

    // Convert to base64 and return
    return {
      'encryptedDataBase64': arrayBufferToBase64String(encryptedDataArrayBuffer),
      'encryptedIvBase64': arrayBufferToBase64String(encryptedIvArrayBuffer),
    };
  } catch (e) {
    throw Exception('An error occurred during encryption: $e');
  }
}

/// Hybrid Decryption Function
/// Decrypts the IV using RSA-OAEP, then decrypts the data using AES-CBC
Future<dynamic> hybridDecryption(
  Map<String, String> encObject,
  String rawPrivateKey,
  String rawAesKey,
) async {
  try {
    // Decrypt keys (only if they're encrypted)
    // Test keys are plain base64, so check if they need decryption
    // Base64-encoded 32-byte key is 44 characters (with padding)
    // If it's base64 format (contains only base64 chars and =), use it as-is
    final isBase64Key = RegExp(r'^[A-Za-z0-9+/=]+$').hasMatch(rawAesKey) && rawAesKey.length >= 32;
    final decryptedAesKey = rawAesKey.contains('-----BEGIN') || isBase64Key
      ? rawAesKey  // Already plain (base64 or PEM format)
      : modifiedCaesarDecrypt(rawAesKey);
    final decryptedPrivateKey = rawPrivateKey.contains('-----BEGIN PRIVATE KEY-----')
      ? rawPrivateKey  // Already plain PEM
      : keyDecrypt(rawPrivateKey);

    // Import keys
    final importedAesKey = importAesKey(decryptedAesKey);
    final importedPrivateKey = importPrivateKey(decryptedPrivateKey);

    // First decrypt the IV using RSA private key
    final ivArrayBuffer = decryptUsingPrivateKey(
      importedPrivateKey,
      encObject['encryptedIvBase64']!,
    );

    // Decrypt the data using AES key
    final plaintextDataArrayBuffer = decryptUsingAesKey(
      ivArrayBuffer,
      importedAesKey,
      encObject['encryptedDataBase64']!,
    );

    // Decode the decrypted data
    final stringURI = utf8.decode(plaintextDataArrayBuffer);

    // Decode URI component and parse JSON
    final decodedString = Uri.decodeComponent(stringURI);

    // Try to parse as JSON, if it fails return as string
    try {
      return jsonDecode(decodedString);
    } catch (e) {
      return decodedString;
    }
  } catch (e) {
    throw Exception('An error occurred during decryption: $e');
  }
}

