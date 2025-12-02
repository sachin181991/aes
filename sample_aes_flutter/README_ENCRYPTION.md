# AES Encryption/Decryption Flutter App

A Flutter application that consumes the hybrid encryption/decryption API service.

## Features

- **Encrypt Data**: Encrypt plaintext using hybrid encryption (AES-CBC + RSA-OAEP)
- **Decrypt Data**: Decrypt encrypted data back to plaintext
- **Server Status**: Real-time connection status indicator
- **Copy to Clipboard**: Easy copying of encrypted/decrypted results

## Setup

1. **Install Dependencies**
   ```bash
   flutter pub get
   ```

2. **Start the Node.js Server**
   - Navigate to the `aes-poc` directory
   - Run `npm install` and then `npm start`
   - Server should be running on `http://localhost:3000`

3. **Configure Server URL**
   - For Android Emulator: Update `baseUrl` in `lib/services/encryption_api_service.dart` to `http://10.0.2.2:3000`
   - For iOS Simulator: Use `http://localhost:3000`
   - For Physical Device: Use your computer's IP address (e.g., `http://192.168.1.100:3000`)

## Running the App

```bash
flutter run
```

## Usage

1. **Encryption**:
   - Enter plaintext data in the "Plaintext Data" field
   - Click "Encrypt" button
   - View the encrypted result (encryptedDataBase64 and encryptedIvBase64)

2. **Decryption**:
   - Enter the encrypted data and encrypted IV (or use values from encryption)
   - Click "Decrypt" button
   - View the decrypted result

## API Integration

The app uses the `EncryptionApiService` to communicate with the Node.js backend:

- `getKeys()`: Fetches default RSA and AES keys
- `encrypt()`: Encrypts plaintext data
- `decrypt()`: Decrypts encrypted data
- `checkHealth()`: Checks server connection status

## Notes

- The app automatically loads default keys from the server on startup
- Server connection status is displayed in the app bar
- All encrypted/decrypted data can be copied to clipboard
- Error messages are displayed in red cards at the top of the screen

