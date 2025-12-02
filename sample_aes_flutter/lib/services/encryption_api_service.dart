import 'dart:convert';
import 'package:http/http.dart' as http;

class EncryptionApiService {
  // Update this to match your server URL
  // For Android emulator, use: http://10.0.2.2:3000
  // For iOS simulator, use: http://localhost:3000
  // For physical device, use your computer's IP: http://192.168.x.x:3000
  static const String baseUrl = 'http://localhost:3000';

  /// Get default keys from the server
  Future<Map<String, dynamic>> getKeys() async {
    try {
      final response = await http.get(
        Uri.parse('$baseUrl/api/keys'),
        headers: {'Content-Type': 'application/json'},
      );

      if (response.statusCode == 200) {
        return json.decode(response.body) as Map<String, dynamic>;
      } else {
        throw Exception('Failed to get keys: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Error getting keys: $e');
    }
  }

  /// Encrypt data
  Future<Map<String, dynamic>> encrypt({
    required dynamic plaintextData,
    String? rawPublicKey,
    String? rawAesKey,
  }) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/encrypt'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'plaintextData': plaintextData,
          if (rawPublicKey != null) 'rawPublicKey': rawPublicKey,
          if (rawAesKey != null) 'rawAesKey': rawAesKey,
        }),
      );

      if (response.statusCode == 200) {
        return json.decode(response.body) as Map<String, dynamic>;
      } else {
        final errorBody = json.decode(response.body);
        throw Exception(errorBody['error'] ?? 'Encryption failed');
      }
    } catch (e) {
      throw Exception('Error encrypting data: $e');
    }
  }

  /// Decrypt data
  Future<Map<String, dynamic>> decrypt({
    required Map<String, String> encryptedData,
    String? rawPrivateKey,
    String? rawAesKey,
  }) async {
    try {
      final response = await http.post(
        Uri.parse('$baseUrl/api/decrypt'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'encryptedData': encryptedData,
          if (rawPrivateKey != null) 'rawPrivateKey': rawPrivateKey,
          if (rawAesKey != null) 'rawAesKey': rawAesKey,
        }),
      );

      if (response.statusCode == 200) {
        return json.decode(response.body) as Map<String, dynamic>;
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

