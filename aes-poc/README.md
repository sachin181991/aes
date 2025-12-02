# AES-POC - Hybrid Encryption/Decryption Service

A Node.js service implementing hybrid encryption using AES-CBC and RSA-OAEP algorithms.

## Features

- **Hybrid Encryption**: Combines AES-CBC (symmetric) and RSA-OAEP (asymmetric) encryption
- **RESTful API**: Simple HTTP endpoints for encryption and decryption
- **Key Management**: Supports encrypted key decryption before use

## Installation

```bash
npm install
```

## Running the Service

```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start
```

The service will run on `http://localhost:3000` by default.

## API Endpoints

### Health Check
```
GET /health
```

### Get Default Keys (for testing)
```
GET /api/keys
```
Returns default RSA key pair and AES key for testing purposes.

### Encrypt Data
```
POST /api/encrypt
Content-Type: application/json

{
  "plaintextData": "Your data to encrypt",
  "rawPublicKey": "optional - RSA public key",
  "rawAesKey": "optional - AES key"
}
```

Response:
```json
{
  "success": true,
  "encryptedData": {
    "encryptedDataBase64": "...",
    "encryptedIvBase64": "..."
  }
}
```

### Decrypt Data
```
POST /api/decrypt
Content-Type: application/json

{
  "encryptedData": {
    "encryptedDataBase64": "...",
    "encryptedIvBase64": "..."
  },
  "rawPrivateKey": "optional - RSA private key",
  "rawAesKey": "optional - AES key"
}
```

Response:
```json
{
  "success": true,
  "decryptedData": "Your decrypted data"
}
```

## Encryption Flow

1. Generate a random 16-byte IV for AES-CBC
2. Encrypt the plaintext data using AES-CBC with the AES key
3. Encrypt the IV using RSA-OAEP with the public key
4. Return both encrypted data and encrypted IV as base64 strings

## Decryption Flow

1. Decrypt the encrypted IV using RSA-OAEP with the private key
2. Use the decrypted IV to decrypt the encrypted data using AES-CBC
3. Return the decrypted plaintext

## Security Notes

- In production, never expose the `/api/keys` endpoint
- Store keys securely using proper key management systems
- Use HTTPS in production
- Implement proper authentication and authorization
- The key decryption functions (`modifiedCaesarDecrypt` and `keyDecrypt`) are placeholders and should be replaced with actual key management logic

