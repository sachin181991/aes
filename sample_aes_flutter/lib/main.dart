import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'services/encryption_api_service.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AES Encryption/Decryption',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const EncryptionDecryptionPage(),
    );
  }
}

class EncryptionDecryptionPage extends StatefulWidget {
  const EncryptionDecryptionPage({super.key});

  @override
  State<EncryptionDecryptionPage> createState() =>
      _EncryptionDecryptionPageState();
}

class _EncryptionDecryptionPageState extends State<EncryptionDecryptionPage> {
  final EncryptionApiService _apiService = EncryptionApiService();
  final TextEditingController _plaintextController = TextEditingController();
  final TextEditingController _encryptedDataController = TextEditingController();
  final TextEditingController _encryptedIvController = TextEditingController();

  String? _publicKey;
  String? _privateKey;
  String? _aesKey;
  bool _isLoading = false;
  String? _errorMessage;
  String? _encryptionResult;
  String? _decryptionResult;
  bool _serverConnected = false;

  @override
  void initState() {
    super.initState();
    _checkServerConnection();
    _loadKeys();
  }

  Future<void> _checkServerConnection() async {
    final connected = await _apiService.checkHealth();
    setState(() {
      _serverConnected = connected;
    });
  }

  Future<void> _loadKeys() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final keys = await _apiService.getKeys();
      setState(() {
        _publicKey = keys['publicKey'] as String?;
        _privateKey = keys['privateKey'] as String?;
        _aesKey = keys['aesKey'] as String?;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = 'Failed to load keys: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _encryptData() async {
    if (_plaintextController.text.isEmpty) {
      setState(() {
        _errorMessage = 'Please enter data to encrypt';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _encryptionResult = null;
    });

    try {
      final result = await _apiService.encrypt(
        plaintextData: _plaintextController.text,
        rawPublicKey: _publicKey,
        rawAesKey: _aesKey,
      );

      if (result['success'] == true) {
        final encryptedData = result['encryptedData'] as Map<String, dynamic>;
        setState(() {
          _encryptionResult = jsonEncode(encryptedData);
          _encryptedDataController.text =
              encryptedData['encryptedDataBase64'] as String? ?? '';
          _encryptedIvController.text =
              encryptedData['encryptedIvBase64'] as String? ?? '';
          _isLoading = false;
        });
      } else {
        setState(() {
          _errorMessage = result['error'] as String? ?? 'Encryption failed';
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Encryption error: $e';
        _isLoading = false;
      });
    }
  }

  Future<void> _decryptData() async {
    if (_encryptedDataController.text.isEmpty ||
        _encryptedIvController.text.isEmpty) {
      setState(() {
        _errorMessage =
            'Please enter both encrypted data and encrypted IV';
      });
      return;
    }

    setState(() {
      _isLoading = true;
      _errorMessage = null;
      _decryptionResult = null;
    });

    try {
      final encryptedData = {
        'encryptedDataBase64': _encryptedDataController.text,
        'encryptedIvBase64': _encryptedIvController.text,
      };

      final result = await _apiService.decrypt(
        encryptedData: encryptedData,
        rawPrivateKey: _privateKey,
        rawAesKey: _aesKey,
      );

      if (result['success'] == true) {
        final decrypted = result['decryptedData'];
        setState(() {
          _decryptionResult = decrypted is Map || decrypted is List
              ? jsonEncode(decrypted)
              : decrypted.toString();
          _isLoading = false;
        });
      } else {
        setState(() {
          _errorMessage = result['error'] as String? ?? 'Decryption failed';
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Decryption error: $e';
        _isLoading = false;
      });
    }
  }

  void _copyToClipboard(String text) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Copied to clipboard')),
    );
  }

  @override
  void dispose() {
    _plaintextController.dispose();
    _encryptedDataController.dispose();
    _encryptedIvController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('AES Encryption/Decryption'),
        actions: [
          IconButton(
            icon: Icon(_serverConnected ? Icons.check_circle : Icons.error),
            color: _serverConnected ? Colors.green : Colors.red,
            onPressed: () {
              _checkServerConnection();
              if (!_serverConnected) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text(
                        'Server not connected. Make sure the Node.js server is running on port 3000.'),
                  ),
                );
              }
            },
          ),
        ],
      ),
      body: _isLoading && _publicKey == null
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Server Status
                  Card(
                    color: _serverConnected ? Colors.green.shade50 : Colors.red.shade50,
                    child: Padding(
                      padding: const EdgeInsets.all(12.0),
                      child: Row(
                        children: [
                          Icon(
                            _serverConnected ? Icons.check_circle : Icons.error,
                            color: _serverConnected ? Colors.green : Colors.red,
                          ),
                          const SizedBox(width: 8),
                          Text(
                            _serverConnected
                                ? 'Server Connected'
                                : 'Server Disconnected',
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: _serverConnected ? Colors.green : Colors.red,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Error Message
                  if (_errorMessage != null)
                    Card(
                      color: Colors.red.shade50,
                      child: Padding(
                        padding: const EdgeInsets.all(12.0),
                        child: Row(
                          children: [
                            const Icon(Icons.error, color: Colors.red),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                _errorMessage!,
                                style: const TextStyle(color: Colors.red),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  if (_errorMessage != null) const SizedBox(height: 16),

                  // Encryption Section
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16.0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          const Text(
                            'Encryption',
                            style: TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 16),
                          TextField(
                            controller: _plaintextController,
                            decoration: const InputDecoration(
                              labelText: 'Plaintext Data',
                              border: OutlineInputBorder(),
                              hintText: 'Enter data to encrypt',
                            ),
                            maxLines: 3,
                          ),
                          const SizedBox(height: 16),
                          ElevatedButton(
                            onPressed: _isLoading ? null : _encryptData,
                            child: _isLoading
                                ? const SizedBox(
                                    height: 20,
                                    width: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  )
                                : const Text('Encrypt'),
                          ),
                          if (_encryptionResult != null) ...[
                            const SizedBox(height: 16),
                            const Text(
                              'Encrypted Result:',
                              style: TextStyle(fontWeight: FontWeight.bold),
                            ),
                            const SizedBox(height: 8),
                            Container(
                              padding: const EdgeInsets.all(12),
                              decoration: BoxDecoration(
                                color: Colors.grey.shade100,
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: SelectableText(
                                _encryptionResult!,
                                style: const TextStyle(fontSize: 12),
                              ),
                            ),
                            const SizedBox(height: 8),
                            Row(
                              children: [
                                Expanded(
                                  child: TextField(
                                    controller: _encryptedDataController,
                                    decoration: const InputDecoration(
                                      labelText: 'Encrypted Data (Base64)',
                                      border: OutlineInputBorder(),
                                    ),
                                    maxLines: 2,
                                  ),
                                ),
                                IconButton(
                                  icon: const Icon(Icons.copy),
                                  onPressed: () => _copyToClipboard(
                                      _encryptedDataController.text),
                                ),
                              ],
                            ),
                            const SizedBox(height: 8),
                            Row(
                              children: [
                                Expanded(
                                  child: TextField(
                                    controller: _encryptedIvController,
                                    decoration: const InputDecoration(
                                      labelText: 'Encrypted IV (Base64)',
                                      border: OutlineInputBorder(),
                                    ),
                                    maxLines: 2,
                                  ),
                                ),
                                IconButton(
                                  icon: const Icon(Icons.copy),
                                  onPressed: () => _copyToClipboard(
                                      _encryptedIvController.text),
                                ),
                              ],
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),

                  // Decryption Section
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16.0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          const Text(
                            'Decryption',
                            style: TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          const SizedBox(height: 16),
                          TextField(
                            controller: _encryptedDataController,
                            decoration: const InputDecoration(
                              labelText: 'Encrypted Data (Base64)',
                              border: OutlineInputBorder(),
                            ),
                            maxLines: 2,
                          ),
                          const SizedBox(height: 16),
                          TextField(
                            controller: _encryptedIvController,
                            decoration: const InputDecoration(
                              labelText: 'Encrypted IV (Base64)',
                              border: OutlineInputBorder(),
                            ),
                            maxLines: 2,
                          ),
                          const SizedBox(height: 16),
                          ElevatedButton(
                            onPressed: _isLoading ? null : _decryptData,
                            child: _isLoading
                                ? const SizedBox(
                                    height: 20,
                                    width: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  )
                                : const Text('Decrypt'),
                          ),
                          if (_decryptionResult != null) ...[
                            const SizedBox(height: 16),
                            const Text(
                              'Decrypted Result:',
                              style: TextStyle(fontWeight: FontWeight.bold),
                            ),
                            const SizedBox(height: 8),
                            Container(
                              padding: const EdgeInsets.all(12),
                              decoration: BoxDecoration(
                                color: Colors.green.shade50,
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: SelectableText(
                                _decryptionResult!,
                                style: const TextStyle(fontSize: 14),
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            ),
    );
  }
}
