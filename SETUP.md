# Hybrid Encryption/Decryption Setup Guide

This project implements a hybrid encryption/decryption system using AES-CBC and RSA-OAEP algorithms, with a Node.js backend service and a Flutter mobile client.

## Project Structure

```
aes/
├── aes-poc/                    # Node.js backend service
│   ├── server.js              # Express server with API endpoints
│   ├── services/              # Encryption/decryption services
│   ├── utils/                 # Crypto utilities and key decryption
│   └── package.json
│
└── sample_aes_flutter/        # Flutter mobile client
    ├── lib/
    │   ├── main.dart          # Main UI
    │   └── services/          # API service
    └── pubspec.yaml
```

## Quick Start

### 1. Setup Node.js Backend

```bash
cd aes-poc
npm install
npm start
```

The server will run on `http://localhost:3000`

### 2. Setup Flutter App

```bash
cd sample_aes_flutter
flutter pub get
flutter run
```

### 3. Configure Server URL (if needed)

For Android Emulator or physical devices, update the `baseUrl` in:
`sample_aes_flutter/lib/services/encryption_api_service.dart`

- Android Emulator: `http://10.0.2.2:3000`
- iOS Simulator: `http://localhost:3000`
- Physical Device: `http://YOUR_COMPUTER_IP:3000`

## API Endpoints

### GET /health
Health check endpoint

### GET /api/keys
Get default RSA key pair and AES key (for testing)

### POST /api/encrypt
Encrypt plaintext data

**Request:**
```json
{
  "plaintextData": "Your data to encrypt",
  "rawPublicKey": "optional",
  "rawAesKey": "optional"
}
```

**Response:**
```json
{
  "success": true,
  "encryptedData": {
    "encryptedDataBase64": "...",
    "encryptedIvBase64": "..."
  }
}
```

### POST /api/decrypt
Decrypt encrypted data

**Request:**
```json
{
  "encryptedData": {
    "encryptedDataBase64": "...",
    "encryptedIvBase64": "..."
  },
  "rawPrivateKey": "optional",
  "rawAesKey": "optional"
}
```

**Response:**
```json
{
  "success": true,
  "decryptedData": "Your decrypted data"
}
```

## Encryption Flow

1. Generate random 16-byte IV for AES-CBC
2. Encrypt plaintext using AES-CBC with AES key
3. Encrypt IV using RSA-OAEP with public key
4. Return both encrypted data and encrypted IV as base64

## Decryption Flow

1. Decrypt encrypted IV using RSA-OAEP with private key
2. Use decrypted IV to decrypt data using AES-CBC
3. Return decrypted plaintext

## Testing

1. Start the Node.js server
2. Launch the Flutter app
3. Enter plaintext in the encryption section
4. Click "Encrypt" to see encrypted results
5. Use the encrypted values in the decryption section
6. Click "Decrypt" to verify the original data

## Security Notes

⚠️ **Important for Production:**

- Remove or secure the `/api/keys` endpoint
- Implement proper key management system
- Use HTTPS in production
- Add authentication and authorization
- Replace placeholder key decryption functions with actual implementation
- Store keys securely (not in code)

## Troubleshooting

### Server Connection Issues

- Ensure Node.js server is running on port 3000
- Check firewall settings
- Verify the baseUrl in Flutter app matches your setup
- For physical devices, ensure device and computer are on same network

### Encryption/Decryption Errors

- Verify keys are properly loaded
- Check that encrypted data format is correct
- Ensure keys match between encryption and decryption

## Dependencies

### Node.js Backend
- express: Web framework
- cors: CORS middleware
- crypto: Built-in Node.js crypto module

### Flutter App
- http: HTTP client for API calls
- flutter: Flutter SDK

