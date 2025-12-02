
import 'dart:convert';
import 'dart:typed_data';

/// Key decryption utilities
/// These functions decrypt the encrypted keys before use

/// Modified Caesar Cipher Decryption for AES Key
/// This is a placeholder - replace with actual decryption logic
String modifiedCaesarDecrypt(String encryptedKey) {
  if (encryptedKey.isEmpty) {
    throw Exception('Encrypted AES key is required');
  }

  // Simple Caesar cipher with shift of 3 (can be customized)
  String decrypted = '';
  const int shift = 3;

  for (int i = 0; i < encryptedKey.length; i++) {
    final char = encryptedKey[i];
    if (char.compareTo('a') >= 0 && char.compareTo('z') <= 0) {
      final charCode = char.codeUnitAt(0);
      final decryptedCode = ((charCode - 'a'.codeUnitAt(0) - shift + 26) % 26) +
          'a'.codeUnitAt(0);
      decrypted += String.fromCharCode(decryptedCode);
    } else if (char.compareTo('A') >= 0 && char.compareTo('Z') <= 0) {
      final charCode = char.codeUnitAt(0);
      final decryptedCode = ((charCode - 'A'.codeUnitAt(0) - shift + 26) % 26) +
          'A'.codeUnitAt(0);
      decrypted += String.fromCharCode(decryptedCode);
    } else if (char.compareTo('0') >= 0 && char.compareTo('9') <= 0) {
      final charCode = char.codeUnitAt(0);
      final decryptedCode = ((charCode - '0'.codeUnitAt(0) - shift + 10) % 10) +
          '0'.codeUnitAt(0);
      decrypted += String.fromCharCode(decryptedCode);
    } else {
      decrypted += char;
    }
  }

  return decrypted;
}

/// Key Decryption for RSA Keys
/// Handles custom PEM headers and decrypts the key content
String keyDecrypt(String encryptedKey) {
  if (encryptedKey.isEmpty) {
    throw Exception('Encrypted key is required');
  }

  String key = encryptedKey;
  bool isPublicKey = false;
  bool isPrivateKey = false;
  
  // Extract base64 content and determine key type
  String base64Content = '';
  
  // Handle custom public key headers
  if (key.contains('-----ILNPU WbISPJ RLf-----')) {
    isPublicKey = true;
    // Extract content between custom headers
    final regex = RegExp(r'-----ILNPU WbISPJ RLf-----(.*?)-----LUK WbISPJ RLf-----', dotAll: true);
    final match = regex.firstMatch(key);
    if (match != null && match.groupCount >= 1) {
      base64Content = match.group(1)!.trim();
    }
  }
  // Handle custom private key headers
  else if (key.contains('-----ILNPU WYPcHaL RLf-----')) {
    isPrivateKey = true;
    // Extract content between custom headers
    final regex = RegExp(r'-----ILNPU WYPcHaL RLf-----(.*?)-----LUK WYPcHaL RLf-----', dotAll: true);
    final match = regex.firstMatch(key);
    if (match != null && match.groupCount >= 1) {
      base64Content = match.group(1)!.trim();
    }
  }
  // Handle standard PEM format
  else if (key.contains('-----BEGIN') && key.contains('-----END')) {
    // Extract content between standard headers
    final regex = RegExp(r'-----BEGIN[^-]+-----\s*(.*?)\s*-----END[^-]+-----', dotAll: true);
    final match = regex.firstMatch(key);
    if (match != null && match.groupCount >= 1) {
      base64Content = match.group(1)!.trim();
      isPublicKey = key.contains('PUBLIC KEY');
      isPrivateKey = key.contains('PRIVATE KEY');
    }
  } else {
    // No headers, assume it's just base64 content
    base64Content = key.trim();
  }

  if (base64Content.isEmpty) {
    throw Exception('No key content found');
  }

  // Try multiple decryption approaches to find the correct one
  String decryptedBase64 = '';
  bool found = false;
  
  // Clean base64 content
  final cleanBase64 = base64Content.replaceAll(RegExp(r'\s+'), '');
  
  // RSA keys use shift 7 (different from AES keys which use shift 3)
  // Try shift 7 first since we know that's correct for RSA keys
  const int rsaKeyShift = 7;
  
  try {
    final testDecrypted = _decryptBase64ContentWithShift(cleanBase64, rsaKeyShift);
    final cleanTest = testDecrypted.replaceAll(RegExp(r'\s+'), '');
    final testBytes = base64Decode(cleanTest);
    // Check if first byte is 0x30 (ASN.1 SEQUENCE tag)
    if (testBytes.isNotEmpty && testBytes[0] == 0x30) {
      decryptedBase64 = testDecrypted;
      found = true;
    }
  } catch (e) {
    // Shift 7 failed - base64 decode might have failed or first byte is wrong
    // This is expected if the shift is wrong, so continue to try other shifts
  }
  
  // If shift 7 didn't work, try other shift values
  if (!found) {
    for (int shift = 1; shift <= 20; shift++) {
      if (shift == rsaKeyShift) continue; // Already tried
      try {
        final testDecrypted = _decryptBase64ContentWithShift(cleanBase64, shift);
        final cleanTest = testDecrypted.replaceAll(RegExp(r'\s+'), '');
        final testBytes = base64Decode(cleanTest);
        if (testBytes.isNotEmpty && testBytes[0] == 0x30) {
          decryptedBase64 = testDecrypted;
          found = true;
          break;
        }
      } catch (e) {
        // Continue to next shift
      }
    }
  }
  
  // Approach 2: If base64 string decryption didn't work, try byte-level decryption
  if (!found) {
    try {
      final encryptedBytes = base64Decode(cleanBase64);
      // Try different byte-level shifts
      for (int shift = 1; shift <= 20; shift++) {
        final decryptedBytes = _decryptBytesWithShift(encryptedBytes, shift);
        if (decryptedBytes.isNotEmpty && decryptedBytes[0] == 0x30) {
          decryptedBase64 = base64Encode(decryptedBytes);
          found = true;
          break;
        }
      }
    } catch (e) {
      // Byte-level decryption failed
    }
  }
  
  if (!found || decryptedBase64.isEmpty) {
    // Debug: Try shift 7 one more time to see what's happening
    String debugInfo = 'Base64 length: ${cleanBase64.length}, First 20 chars: ${cleanBase64.length > 20 ? cleanBase64.substring(0, 20) : cleanBase64}';
    try {
      final testDecrypted = _decryptBase64ContentWithShift(cleanBase64, 7);
      final cleanTest = testDecrypted.replaceAll(RegExp(r'\s+'), '');
      debugInfo += ', Decrypted length: ${cleanTest.length}';
      final testBytes = base64Decode(cleanTest);
      debugInfo += ', Decoded ${testBytes.length} bytes, first byte: 0x${testBytes.isNotEmpty ? testBytes[0].toRadixString(16).padLeft(2, '0') : 'empty'}';
      if (testBytes.isNotEmpty && testBytes[0] != 0x30) {
        debugInfo += ' (expected 0x30)';
      }
    } catch (e) {
      debugInfo += ', Shift 7 error: $e';
    }
    
    throw Exception('Failed to decrypt key content - all decryption methods failed. $debugInfo');
  }

  // Reconstruct PEM format with standard headers
  String formattedKey = '';
  final finalBase64 = decryptedBase64.replaceAll(RegExp(r'\s+'), '');
  
  for (int i = 0; i < finalBase64.length; i += 64) {
    final end = (i + 64 < finalBase64.length) ? i + 64 : finalBase64.length;
    formattedKey += finalBase64.substring(i, end) + '\n';
  }

  if (isPublicKey) {
    return '-----BEGIN PUBLIC KEY-----\n$formattedKey-----END PUBLIC KEY-----';
  } else if (isPrivateKey) {
    return '-----BEGIN PRIVATE KEY-----\n$formattedKey-----END PRIVATE KEY-----';
  } else {
    // Default to public key if type is unknown
    return '-----BEGIN PUBLIC KEY-----\n$formattedKey-----END PUBLIC KEY-----';
  }
}

/// Decrypt base64 content using modified Caesar cipher
/// Base64 characters: A-Z, a-z, 0-9, +, /, =
String _decryptBase64Content(String encryptedBase64) {
  String decrypted = '';
  const int shift = 3; // Same shift as modifiedCaesarDecrypt

  for (int i = 0; i < encryptedBase64.length; i++) {
    final char = encryptedBase64[i];
    
    // Handle base64 alphabet: A-Z (0-25), a-z (26-51), 0-9 (52-61), + (62), / (63), = (padding)
    if (char.compareTo('A') >= 0 && char.compareTo('Z') <= 0) {
      // Uppercase letters: A=0, B=1, ..., Z=25
      final charCode = char.codeUnitAt(0);
      final decryptedCode = ((charCode - 'A'.codeUnitAt(0) - shift + 26) % 26) + 'A'.codeUnitAt(0);
      decrypted += String.fromCharCode(decryptedCode);
    } else if (char.compareTo('a') >= 0 && char.compareTo('z') <= 0) {
      // Lowercase letters: a=26, b=27, ..., z=51
      final charCode = char.codeUnitAt(0);
      final decryptedCode = ((charCode - 'a'.codeUnitAt(0) - shift + 26) % 26) + 'a'.codeUnitAt(0);
      decrypted += String.fromCharCode(decryptedCode);
    } else if (char.compareTo('0') >= 0 && char.compareTo('9') <= 0) {
      // Digits: 0=52, 1=53, ..., 9=61
      final charCode = char.codeUnitAt(0);
      final decryptedCode = ((charCode - '0'.codeUnitAt(0) - shift + 10) % 10) + '0'.codeUnitAt(0);
      decrypted += String.fromCharCode(decryptedCode);
    } else if (char == '+') {
      // + is 62 in base64, decrypt to / (63) or wrap around
      // For simplicity, keep + as is or map: + -> / -> = -> + (cyclic)
      // Since + is at position 62, shifting by 3: (62-3+64)%64 = 59, which is '7'
      // Actually, let's map base64 chars: A-Z=0-25, a-z=26-51, 0-9=52-61, +=62, /=63
      // For + (62): (62-3+64)%64 = 59 -> '7'
      // This is complex, let's try a simpler approach: just shift the character codes
      // But + and / are special, so we need to handle them differently
      // For now, let's try mapping: + -> /, / -> =, = -> A (cyclic with base64 alphabet)
      final base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
      final charIndex = base64Chars.indexOf(char);
      if (charIndex >= 0) {
        final decryptedIndex = (charIndex - shift + base64Chars.length) % base64Chars.length;
        decrypted += base64Chars[decryptedIndex];
      } else {
        decrypted += char;
      }
    } else if (char == '/') {
      final base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
      final charIndex = base64Chars.indexOf(char);
      if (charIndex >= 0) {
        final decryptedIndex = (charIndex - shift + base64Chars.length) % base64Chars.length;
        decrypted += base64Chars[decryptedIndex];
      } else {
        decrypted += char;
      }
    } else if (char == '=') {
      // Padding character, usually keep as is
      decrypted += char;
    } else {
      // Whitespace or other characters, keep as is
      decrypted += char;
    }
  }

  return decrypted;
}

/// Decrypt base64 content with a specific shift value
String _decryptBase64ContentWithShift(String encryptedBase64, int shift) {
  const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
  String decrypted = '';
  
  for (int i = 0; i < encryptedBase64.length; i++) {
    final char = encryptedBase64[i];
    final charIndex = base64Chars.indexOf(char);
    
    if (charIndex >= 0) {
      final decryptedIndex = (charIndex - shift + base64Chars.length) % base64Chars.length;
      decrypted += base64Chars[decryptedIndex];
    } else {
      decrypted += char;
    }
  }
  
  return decrypted;
}

/// Decrypt bytes with a specific shift value
Uint8List _decryptBytesWithShift(Uint8List encryptedBytes, int shift) {
  final decrypted = Uint8List(encryptedBytes.length);
  
  for (int i = 0; i < encryptedBytes.length; i++) {
    decrypted[i] = (encryptedBytes[i] - shift + 256) % 256;
  }
  
  return decrypted;
}

