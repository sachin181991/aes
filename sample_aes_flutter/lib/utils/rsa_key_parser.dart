import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

/// Parse RSA Public Key from PEM format
RSAPublicKey parseRSAPublicKeyFromPEM(String pemString) {
  try {
    // Remove PEM headers and whitespace
    String keyBase64 = pemString
        .replaceAll('-----BEGIN PUBLIC KEY-----', '')
        .replaceAll('-----END PUBLIC KEY-----', '')
        .replaceAll(RegExp(r'\s+'), '');
    
    // Also handle any other BEGIN/END markers
    if (keyBase64.isEmpty || keyBase64.length < 10) {
      // Try to extract base64 using regex
      final regex = RegExp(r'-----BEGIN[^-]+-----\s*([A-Za-z0-9+/=\s]+)\s*-----END[^-]+-----');
      final match = regex.firstMatch(pemString);
      if (match != null && match.groupCount >= 1) {
        keyBase64 = match.group(1)!.replaceAll(RegExp(r'\s+'), '');
      }
    }
    
    if (keyBase64.isEmpty) {
      throw Exception('No base64 content found in PEM string. PEM length: ${pemString.length}');
    }
    
    Uint8List keyBytes;
    try {
      keyBytes = base64Decode(keyBase64);
    } catch (e) {
      throw Exception('Failed to decode base64: $e. Base64 length: ${keyBase64.length}, First 50 chars: ${keyBase64.length > 50 ? keyBase64.substring(0, 50) : keyBase64}');
    }
    
    if (keyBytes.isEmpty) {
      throw Exception('Decoded key bytes are empty');
    }
    
    // Simple ASN.1 parsing for RSA public key
    // SubjectPublicKeyInfo structure: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    int offset = 0;
    
    // Check for SEQUENCE tag (0x30)
    if (offset >= keyBytes.length) {
      throw Exception('Key bytes are empty');
    }
    
    final firstByte = keyBytes[offset];
    if (firstByte != 0x30) {
      throw Exception('Invalid ASN.1 structure: expected SEQUENCE (0x30) at offset $offset, got 0x${firstByte.toRadixString(16).padLeft(2, '0')}. Key bytes length: ${keyBytes.length}, First 10 bytes: ${keyBytes.take(10).map((b) => '0x${b.toRadixString(16).padLeft(2, '0')}').join(', ')}');
    }
    offset++; // Skip SEQUENCE tag
    
    // Read outer SEQUENCE length
    final seqLength = _readLength(keyBytes, offset);
    offset += seqLength.lengthBytes;
    
    // Verify we have enough bytes
    if (offset + seqLength.value > keyBytes.length) {
      throw Exception('Invalid ASN.1 structure: not enough bytes for sequence');
    }
    
    // Skip AlgorithmIdentifier (we know it's RSA)
    if (offset >= keyBytes.length || keyBytes[offset] != 0x30) {
      throw Exception('Invalid ASN.1 structure: expected AlgorithmIdentifier SEQUENCE');
    }
    offset++; // Skip SEQUENCE tag
    final algSeqLength = _readLength(keyBytes, offset);
    offset += algSeqLength.lengthBytes + algSeqLength.value;
    
    // Read BIT STRING (tag 0x03)
    if (offset >= keyBytes.length || keyBytes[offset] != 0x03) {
      throw Exception('Invalid ASN.1 structure: expected BIT STRING');
    }
    offset++; // Skip BIT STRING tag
    final bitStringLength = _readLength(keyBytes, offset);
    offset += bitStringLength.lengthBytes;
    
    // Verify we have enough bytes for the bit string
    if (offset + bitStringLength.value > keyBytes.length) {
      throw Exception('Invalid ASN.1 structure: not enough bytes for bit string');
    }
    
    offset++; // Skip unused bits byte
    
    // Store the end of the bit string for bounds checking
    final bitStringEnd = offset + bitStringLength.value - 1; // -1 because we already skipped the unused bits byte
    
    // Parse RSAPublicKey structure from BIT STRING
    // RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    if (offset >= keyBytes.length || keyBytes[offset] != 0x30) {
      throw Exception('Invalid ASN.1 structure: expected RSAPublicKey SEQUENCE at offset $offset');
    }
    offset++; // Skip SEQUENCE tag
    final rsaSeqLength = _readLength(keyBytes, offset);
    offset += rsaSeqLength.lengthBytes;
    
    // Verify we have enough bytes for RSA sequence (within bit string bounds)
    if (offset + rsaSeqLength.value > bitStringEnd) {
      throw Exception('Invalid ASN.1 structure: RSA sequence extends beyond bit string. Offset: $offset, Length: ${rsaSeqLength.value}, BitStringEnd: $bitStringEnd');
    }
    
    // Read modulus (INTEGER tag 0x02)
    if (offset >= keyBytes.length || keyBytes[offset] != 0x02) {
      throw Exception('Invalid ASN.1 structure: expected modulus INTEGER');
    }
    offset++; // Skip INTEGER tag
    final modulusLength = _readLength(keyBytes, offset);
    offset += modulusLength.lengthBytes;
    
    // Verify we have enough bytes for modulus
    if (offset + modulusLength.value > keyBytes.length) {
      throw Exception('Invalid ASN.1 structure: not enough bytes for modulus');
    }
    
    final modulusBytes = keyBytes.sublist(offset, offset + modulusLength.value);
    offset += modulusLength.value;
    final modulus = _bytesToBigInteger(modulusBytes);
    
    // Read public exponent (INTEGER tag 0x02)
    if (offset >= keyBytes.length || keyBytes[offset] != 0x02) {
      throw Exception('Invalid ASN.1 structure: expected exponent INTEGER');
    }
    offset++; // Skip INTEGER tag
    final exponentLength = _readLength(keyBytes, offset);
    offset += exponentLength.lengthBytes;
    
    // Verify we have enough bytes for exponent
    if (offset + exponentLength.value > keyBytes.length) {
      throw Exception('Invalid ASN.1 structure: not enough bytes for exponent');
    }
    
    final exponentBytes = keyBytes.sublist(offset, offset + exponentLength.value);
    final exponent = _bytesToBigInteger(exponentBytes);
    
    return RSAPublicKey(modulus, exponent);
  } catch (e) {
    throw Exception('Failed to parse RSA public key: $e');
  }
}

/// Parse RSA Private Key from PEM format
RSAPrivateKey parseRSAPrivateKeyFromPEM(String pemString) {
  // Remove PEM headers and whitespace
  final keyBase64 = pemString
      .replaceAll('-----BEGIN PRIVATE KEY-----', '')
      .replaceAll('-----END PRIVATE KEY-----', '')
      .replaceAll(RegExp(r'\s+'), '');
  
  final keyBytes = base64Decode(keyBase64);
  
  // Simple ASN.1 parsing for RSA private key
  // PrivateKeyInfo: SEQUENCE { version INTEGER, AlgorithmIdentifier, OCTET STRING }
  int offset = 0;
  
  // Check for SEQUENCE tag (0x30)
  if (offset >= keyBytes.length || keyBytes[offset] != 0x30) {
    throw Exception('Invalid ASN.1 structure: expected SEQUENCE (0x30) at offset $offset');
  }
  offset++; // Skip SEQUENCE tag
  
  // Read SEQUENCE length (can be short or long form)
  final seqLength = _readLength(keyBytes, offset);
  offset += seqLength.lengthBytes;
  
  // Skip version INTEGER
  if (offset >= keyBytes.length || keyBytes[offset] != 0x02) {
    throw Exception('Invalid ASN.1 structure: expected version INTEGER at offset $offset');
  }
  offset++; // Skip INTEGER tag
  final versionLength = _readLength(keyBytes, offset);
  offset += versionLength.lengthBytes + versionLength.value; // Skip length and value
  
  // Skip AlgorithmIdentifier SEQUENCE
  if (offset >= keyBytes.length || keyBytes[offset] != 0x30) {
    throw Exception('Invalid ASN.1 structure: expected AlgorithmIdentifier SEQUENCE at offset $offset');
  }
  offset++; // Skip SEQUENCE tag
  final algSeqLength = _readLength(keyBytes, offset);
  offset += algSeqLength.lengthBytes + algSeqLength.value;
  
  // Read OCTET STRING
  if (offset >= keyBytes.length || keyBytes[offset] != 0x04) {
    throw Exception('Invalid ASN.1 structure: expected OCTET STRING (0x04) at offset $offset');
  }
  offset++; // Skip OCTET STRING tag
  final octetStringLength = _readLength(keyBytes, offset);
  offset += octetStringLength.lengthBytes;
  
  // Parse RSAPrivateKey structure from OCTET STRING
  // RSAPrivateKey: SEQUENCE { version, modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient }
  if (offset >= keyBytes.length || keyBytes[offset] != 0x30) {
    throw Exception('Invalid ASN.1 structure: expected RSAPrivateKey SEQUENCE at offset $offset');
  }
  offset++; // Skip SEQUENCE tag
  final rsaSeqLength = _readLength(keyBytes, offset);
  offset += rsaSeqLength.lengthBytes;
  
  // Skip version INTEGER
  if (offset >= keyBytes.length || keyBytes[offset] != 0x02) {
    throw Exception('Invalid ASN.1 structure: expected version INTEGER at offset $offset');
  }
  offset++; // Skip INTEGER tag
  final rsaVersionLength = _readLength(keyBytes, offset);
  offset += rsaVersionLength.lengthBytes + rsaVersionLength.value; // Skip length and value
  
  // Read modulus
  offset++; // Skip INTEGER tag
  final modulusLength = _readLength(keyBytes, offset);
  offset += modulusLength.lengthBytes;
  final modulusBytes = keyBytes.sublist(offset, offset + modulusLength.value);
  offset += modulusLength.value;
  final modulus = _bytesToBigInteger(modulusBytes);
  
  // Skip public exponent
  offset++; // Skip INTEGER tag
  final pubExpLength = _readLength(keyBytes, offset);
  offset += pubExpLength.lengthBytes + pubExpLength.value;
  
  // Read private exponent
  offset++; // Skip INTEGER tag
  final privExpLength = _readLength(keyBytes, offset);
  offset += privExpLength.lengthBytes;
  final privExpBytes = keyBytes.sublist(offset, offset + privExpLength.value);
  offset += privExpLength.value;
  final privateExponent = _bytesToBigInteger(privExpBytes);
  
  // Read prime1
  offset++; // Skip INTEGER tag
  final prime1Length = _readLength(keyBytes, offset);
  offset += prime1Length.lengthBytes;
  final prime1Bytes = keyBytes.sublist(offset, offset + prime1Length.value);
  offset += prime1Length.value;
  final prime1 = _bytesToBigInteger(prime1Bytes);
  
  // Read prime2
  offset++; // Skip INTEGER tag
  final prime2Length = _readLength(keyBytes, offset);
  offset += prime2Length.lengthBytes;
  final prime2Bytes = keyBytes.sublist(offset, offset + prime2Length.value);
  offset += prime2Length.value;
  final prime2 = _bytesToBigInteger(prime2Bytes);
  
  // Read exponent1 (d mod (p-1))
  offset++; // Skip INTEGER tag
  final exp1Length = _readLength(keyBytes, offset);
  offset += exp1Length.lengthBytes;
  offset += exp1Length.value; // Skip exponent1
  
  // Read exponent2 (d mod (q-1))
  offset++; // Skip INTEGER tag
  final exp2Length = _readLength(keyBytes, offset);
  offset += exp2Length.lengthBytes;
  offset += exp2Length.value; // Skip exponent2
  
  // Read coefficient (q^-1 mod p)
  offset++; // Skip INTEGER tag
  final coeffLength = _readLength(keyBytes, offset);
  offset += coeffLength.lengthBytes;
  offset += coeffLength.value; // Skip coefficient
  
  // RSAPrivateKey constructor: RSAPrivateKey(n, d, p, q)
  return RSAPrivateKey(
    modulus,
    privateExponent,
    prime1,
    prime2,
  );
}

class _Length {
  final int value;
  final int lengthBytes;
  _Length(this.value, this.lengthBytes);
}

_Length _readLength(Uint8List bytes, int offset) {
  if (offset >= bytes.length) {
    throw Exception('Invalid offset: $offset, bytes length: ${bytes.length}');
  }
  
  final firstByte = bytes[offset];
  if ((firstByte & 0x80) == 0) {
    // Short form
    return _Length(firstByte, 1);
  } else {
    // Long form
    final lengthOfLength = firstByte & 0x7F;
    
    // Sanity check: lengthOfLength should be reasonable (max 4 bytes for 32-bit length)
    if (lengthOfLength > 4 || lengthOfLength == 0) {
      throw Exception('Invalid length of length: $lengthOfLength at offset $offset');
    }
    
    if (offset + 1 + lengthOfLength > bytes.length) {
      throw Exception('Not enough bytes for length at offset $offset');
    }
    
    int length = 0;
    for (int i = 0; i < lengthOfLength; i++) {
      length = (length << 8) | bytes[offset + 1 + i];
    }
    
    // Sanity check: length should be reasonable
    if (length > bytes.length || length < 0) {
      throw Exception('Invalid length value: $length at offset $offset');
    }
    
    return _Length(length, 1 + lengthOfLength);
  }
}

BigInt _bytesToBigInteger(Uint8List bytes) {
  // Handle sign bit
  if (bytes[0] & 0x80 != 0) {
    // Negative number, but RSA keys are always positive
    // Prepend zero byte
    final positiveBytes = Uint8List(bytes.length + 1);
    positiveBytes[0] = 0;
    positiveBytes.setRange(1, positiveBytes.length, bytes);
    return _decodeBigInt(positiveBytes);
  }
  return _decodeBigInt(bytes);
}

BigInt _decodeBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < bytes.length; i++) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

