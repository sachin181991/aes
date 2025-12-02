import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'rsa_key_parser.dart';

/// Import AES Key from raw key string
/// Ensures key is 32 bytes (256 bits) for AES-256
/// Handles both base64-encoded keys and plain text keys
Uint8List importAesKey(String rawAesKey) {
  if (rawAesKey.isEmpty) {
    throw Exception('AES key is required');
  }

  Uint8List keyBytes;
  
  // Check if it's base64 encoded (test keys are base64)
  try {
    // Try to decode as base64 first
    keyBytes = base64Decode(rawAesKey);
    // If decode succeeds and length is reasonable, use it
    if (keyBytes.length >= 16 && keyBytes.length <= 64) {
      // Base64 decoded successfully, use it
    } else {
      // Base64 decode produced unexpected length, treat as plain text
      keyBytes = utf8.encode(rawAesKey);
    }
  } catch (e) {
    // Not base64, treat as plain text
    keyBytes = utf8.encode(rawAesKey);
  }

  // Ensure key is exactly 32 bytes
  if (keyBytes.length < 32) {
    // Pad with zeros
    final paddedKey = Uint8List(32);
    paddedKey.setRange(0, keyBytes.length, keyBytes);
    return paddedKey;
  } else if (keyBytes.length > 32) {
    // Truncate to 32 bytes
    return Uint8List.fromList(keyBytes.sublist(0, 32));
  }

  return Uint8List.fromList(keyBytes);
}

/// Import RSA Public Key from PEM format
RSAPublicKey importPublicKey(String rawPublicKey) {
  if (rawPublicKey.isEmpty) {
    throw Exception('Public key is required');
  }

  try {
    // Clean up the key
    String pemKey = rawPublicKey.trim();

    // Extract base64 content if it's in PEM format
    String base64Content = '';
    if (pemKey.contains('-----BEGIN') && pemKey.contains('-----END')) {
      // Use regex to extract content between headers (handles any header format)
      final regex = RegExp(r'-----BEGIN[^-]+-----\s*([\s\S]*?)\s*-----END[^-]+-----');
      final match = regex.firstMatch(pemKey);
      if (match != null && match.groupCount >= 1) {
        base64Content = match.group(1)!;
      } else {
        // Fallback: manual extraction
        final beginMarker = '-----BEGIN';
        final endMarker = '-----END';
        final beginIndex = pemKey.indexOf(beginMarker);
        final endIndex = pemKey.indexOf(endMarker, beginIndex + beginMarker.length);
        
        if (beginIndex >= 0 && endIndex > beginIndex) {
          // Find the first newline after BEGIN marker
          final beginEnd = pemKey.indexOf('\n', beginIndex);
          final startContent = beginEnd > 0 ? beginEnd + 1 : pemKey.indexOf('-----', beginIndex + beginMarker.length) + 5;
          
          // Find the last newline before END marker
          final endStart = pemKey.lastIndexOf('\n', endIndex);
          final endContent = endStart > 0 ? endStart : endIndex;
          
          if (startContent > 0 && endContent > startContent) {
            base64Content = pemKey.substring(startContent, endContent);
          }
        }
      }
    } else {
      // No PEM headers, assume it's just base64
      base64Content = pemKey.replaceAll(RegExp(r'\s+'), '');
    }

    // Clean up base64 content
    base64Content = base64Content.replaceAll(RegExp(r'\s+'), '');
    
    if (base64Content.isEmpty) {
      throw Exception('No base64 content found in key');
    }

    // Reconstruct proper PEM format
    String formattedKey = '';
    for (int i = 0; i < base64Content.length; i += 64) {
      final end = (i + 64 < base64Content.length) ? i + 64 : base64Content.length;
      formattedKey += base64Content.substring(i, end) + '\n';
    }

    final properPemKey = '-----BEGIN PUBLIC KEY-----\n$formattedKey-----END PUBLIC KEY-----';

    // Try parsing with proper PEM format
    try {
      return parseRSAPublicKeyFromPEM(properPemKey);
    } catch (e1) {
      // If parsing fails, try with the original key format
      try {
        return parseRSAPublicKeyFromPEM(pemKey);
      } catch (e2) {
        // Last resort: try to decode base64 directly and parse
        try {
          final keyBytes = base64Decode(base64Content);
          // Try to find the RSA public key structure
          return _parseRSAPublicKeyFromDER(keyBytes);
        } catch (e3) {
          throw Exception('Failed to import public key. Attempt 1: $e1. Attempt 2: $e2. Attempt 3: $e3');
        }
      }
    }
  } catch (e) {
    throw Exception('Failed to import public key: $e');
  }
}

/// Parse RSA Public Key directly from DER bytes (fallback method)
RSAPublicKey _parseRSAPublicKeyFromDER(Uint8List keyBytes) {
  // Use the existing parser but construct a fake PEM
  final base64Key = base64Encode(keyBytes);
  String formattedKey = '';
  for (int i = 0; i < base64Key.length; i += 64) {
    final end = (i + 64 < base64Key.length) ? i + 64 : base64Key.length;
    formattedKey += base64Key.substring(i, end) + '\n';
  }
  final fakePem = '-----BEGIN PUBLIC KEY-----\n$formattedKey-----END PUBLIC KEY-----';
  return parseRSAPublicKeyFromPEM(fakePem);
}


/// Import RSA Private Key from PEM format
RSAPrivateKey importPrivateKey(String rawPrivateKey) {
  if (rawPrivateKey.isEmpty) {
    throw Exception('Private key is required');
  }

  try {
    // Clean up the key
    String pemKey = rawPrivateKey.trim();

    // If it already has PEM headers, use it as is
    if (!pemKey.contains('-----BEGIN')) {
      // If no headers, try to add them
      final keyContent = pemKey.replaceAll(RegExp(r'\s+'), '');

      // Format as PEM with 64 characters per line
      String formattedKey = '';
      for (int i = 0; i < keyContent.length; i += 64) {
        final end = (i + 64 < keyContent.length) ? i + 64 : keyContent.length;
        formattedKey += keyContent.substring(i, end) + '\n';
      }

      pemKey = '-----BEGIN PRIVATE KEY-----\n$formattedKey-----END PRIVATE KEY-----';
    }

    // Parse PEM format
    return parseRSAPrivateKeyFromPEM(pemKey);
  } catch (e) {
    throw Exception('Failed to import private key: $e');
  }
}

/// Encrypt data using AES-CBC
Uint8List encryptUsingAesKey(Uint8List iv, Uint8List aesKey, String plaintext) {
  try {
    final key = KeyParameter(aesKey);
    final ivParam = ParametersWithIV(key, iv);
    final params = PaddedBlockCipherParameters(ivParam, null);

    final cipher = PaddedBlockCipher('AES/CBC/PKCS7');
    cipher.init(true, params);

    final plaintextBytes = utf8.encode(plaintext);
    final encrypted = cipher.process(plaintextBytes);

    return Uint8List.fromList(encrypted);
  } catch (e) {
    throw Exception('AES encryption failed: $e');
  }
}

/// Encrypt IV using RSA-OAEP
/// Note: pointycastle's OAEPEncoding uses SHA-1 by default
Uint8List encryptUsingPublicKey(RSAPublicKey publicKey, Uint8List iv) {
  try {
    // IV is 16 bytes, which is well within limits for any RSA key size
    // For 2048-bit RSA with OAEP-SHA-1: max ~214 bytes
    // Remove size check as it's causing issues and 16 bytes is always safe
    
    // Create OAEP encoding (uses SHA-1 by default in pointycastle)
    final cipher = OAEPEncoding(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

    final encrypted = cipher.process(iv);

    return Uint8List.fromList(encrypted);
  } catch (e) {
    throw Exception('RSA encryption failed: $e');
  }
}

/// Decrypt IV using RSA-OAEP
/// Note: Uses SHA-1 by default (matching encryption)
Uint8List decryptUsingPrivateKey(RSAPrivateKey privateKey, String encryptedIvBase64) {
  try {
    final encryptedIv = base64Decode(encryptedIvBase64);

    // Create OAEP encoding (uses SHA-1 by default)
    final cipher = OAEPEncoding(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

    final decrypted = cipher.process(encryptedIv);

    return Uint8List.fromList(decrypted);
  } catch (e) {
    throw Exception('RSA decryption failed: $e');
  }
}

/// Decrypt data using AES-CBC
Uint8List decryptUsingAesKey(Uint8List iv, Uint8List aesKey, String encryptedDataBase64) {
  try {
    final encryptedData = base64Decode(encryptedDataBase64);

    final key = KeyParameter(aesKey);
    final ivParam = ParametersWithIV(key, iv);
    final params = PaddedBlockCipherParameters(ivParam, null);

    final cipher = PaddedBlockCipher('AES/CBC/PKCS7');
    cipher.init(false, params);

    final decrypted = cipher.process(encryptedData);

    return Uint8List.fromList(decrypted);
  } catch (e) {
    throw Exception('AES decryption failed: $e');
  }
}

/// Convert Uint8List to Base64 string
String arrayBufferToBase64String(Uint8List buffer) {
  return base64Encode(buffer);
}

/// Generate random bytes
Uint8List generateRandomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}

