import 'dart:convert';
import 'dart:developer' show log;
import 'package:http/http.dart' as http;
import '../services/encryption_service.dart';

class EncryptionApiService {
  // Update this to match your server URL
  // For Android emulator, use: http://10.0.2.2:3000
  // For iOS simulator, use: http://localhost:3000
  // For physical device, use your computer's IP: http://192.168.x.x:3000
  static const String baseUrl = 'http://localhost:3000';

  String? _publicKey;
  String? _privateKey;
  String? _aesKey;

  /// Get default keys from the server
  Future<Map<String, dynamic>> getKeys() async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/api/keys'),
        headers: {'Content-Type': 'application/json'},
      );

      if (response.statusCode == 200) {
        final keys = json.decode(response.body) as Map<String, dynamic>;
        _publicKey = keys['publicKey'] as String?;
        _privateKey = keys['privateKey'] as String?;
        _aesKey = keys['aesKey'] as String?;
        return keys;
      } else {
        throw Exception('Failed to get keys: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Error getting keys: $e');
    }
  }

  /// Set keys manually
  void setKeys({
    String? publicKey,
    String? privateKey,
    String? aesKey,
  }) {
    if (publicKey != null) _publicKey = publicKey;
    if (privateKey != null) _privateKey = privateKey;
    if (aesKey != null) _aesKey = aesKey;
  }

  /// Encrypt data (encrypts request, sends encrypted data, decrypts response)
  Future<Map<String, dynamic>> encrypt({
    required dynamic plaintextData,
    String? rawPublicKey,
    String? rawAesKey,
  }) async {
    try {
      // Use provided keys or stored keys
      final publicKey = rawPublicKey ?? _publicKey;
      final aesKey = rawAesKey ?? _aesKey;

      if (publicKey == null || aesKey == null) {
        throw Exception('Public key and AES key are required');
      }

      // Encrypt the plaintext data on Flutter side
      final encryptedData = await hybridEncryption(
        plaintextData,
        publicKey,
        aesKey,
      );

      log('Encrypted data: $encryptedData');

      // Send encrypted data to server (server will decrypt it)
      final response = await http.post(
        Uri.parse('$baseUrl/api/encrypt'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'encryptedData': encryptedData,
        }),
      );

      if (response.statusCode == 200) {
        final responseBody = json.decode(response.body) as Map<String, dynamic>;

        log('Response body: $responseBody');
        
        // Server returns encrypted response, decrypt it
        if (responseBody.containsKey('encryptedData')) {
          log('Encrypted data found');
          final encryptedResponse = responseBody['encryptedData'] as Map<String, dynamic>;
          final encryptedResponseMap = {
            'encryptedDataBase64': encryptedResponse['encryptedDataBase64'] as String,
            'encryptedIvBase64': encryptedResponse['encryptedIvBase64'] as String,
          };
          log('Encrypted before decrypt');

          var decryptedResponse = null;
          // Decrypt the response
          try {
             decryptedResponse = await hybridDecryption(
            encryptedResponseMap,
            _privateKey!,
            aesKey,
          );
          } catch (e) {
            log('Error decrypting data: $e');
            // If decryption fails, return the encrypted data as-is
            decryptedResponse = encryptedResponseMap;
          }

          log('Decrypted response: $decryptedResponse');

          return {
            'success': true,
            'encryptedData': encryptedResponseMap,
            'decryptedData': decryptedResponse,
          };
        }

        return responseBody;
      } else {
        final errorBody = json.decode(response.body);
        throw Exception(errorBody['error'] ?? 'Encryption failed');
      }
    } catch (e) {
      throw Exception('Error encrypting data: $e');
    }
  }

  /// Decrypt data (encrypts request, sends encrypted data, decrypts response)
  Future<Map<String, dynamic>> decrypt({
    required Map<String, String> encryptedData,
    String? rawPrivateKey,
    String? rawAesKey,
  }) async {
    try {
      // Use provided keys or stored keys
      final privateKey = rawPrivateKey ?? _privateKey;
      final aesKey = rawAesKey ?? _aesKey;

      if (privateKey == null || aesKey == null) {
        throw Exception('Private key and AES key are required');
      }

      // Encrypt the request data (encryptedData) before sending
      final publicKey = _publicKey;
      if (publicKey == null) {
        throw Exception('Public key is required for encrypting request');
      }

      final encryptedRequest = await hybridEncryption(
        jsonEncode(encryptedData),
        publicKey,
        aesKey,
      );

      // Send encrypted request to server
      final response = await http.post(
        Uri.parse('$baseUrl/api/decrypt'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'encryptedData': encryptedRequest,
        }),
      );

      if (response.statusCode == 200) {
        final responseBody = json.decode(response.body) as Map<String, dynamic>;
        
        // Server returns encrypted response, decrypt it
        if (responseBody.containsKey('encryptedData')) {
          final encryptedResponse = responseBody['encryptedData'] as Map<String, dynamic>;
          final encryptedResponseMap = {
            'encryptedDataBase64': encryptedResponse['encryptedDataBase64'] as String,
            'encryptedIvBase64': encryptedResponse['encryptedIvBase64'] as String,
          };

          // Decrypt the response
          final decryptedResponse = await hybridDecryption(
            encryptedResponseMap,
            privateKey,
            aesKey,
          );

          return {
            'success': true,
            'decryptedData': decryptedResponse,
          };
        }

        return responseBody;
      } else {
        final errorBody = json.decode(response.body);
        throw Exception(errorBody['error'] ?? 'Decryption failed');
      }
    } catch (e) {
      throw Exception('Error decrypting data: $e');
    }
  }

  /// Check server health
  Future<bool> checkHealth() async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/health'),
        headers: {'Content-Type': 'application/json'},
      );

      return response.statusCode == 200;
    } catch (e) {
      return false;
    }
  }
}
