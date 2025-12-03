# Hybrid Encryption/Decryption - Technical Documentation

## Executive Summary

This project implements **Hybrid Encryption** combining:
- **AES-CBC** (Advanced Encryption Standard - Cipher Block Chaining) for symmetric encryption of data
- **RSA-OAEP** (Rivest-Shamir-Adleman - Optimal Asymmetric Encryption Padding) for asymmetric encryption of the Initialization Vector (IV)

This approach leverages the speed of symmetric encryption for bulk data while using asymmetric encryption for secure key exchange.

---

## Table of Contents

1. [Encryption Type](#encryption-type)
2. [Key Specifications](#key-specifications)
3. [Algorithm Parameters](#algorithm-parameters)
4. [Key Formats](#key-formats)
5. [Node.js Implementation Details](#nodejs-implementation-details)
6. [Flutter Implementation Details](#flutter-implementation-details)
7. [Complete Encryption Flow](#complete-encryption-flow)
8. [Complete Decryption Flow](#complete-decryption-flow)
9. [Data Formats & Encoding](#data-formats--encoding)
10. [Code Structure](#code-structure)

---

## Encryption Type

**Hybrid Encryption** - A combination of:
- **Symmetric Encryption (AES-CBC)**: Used to encrypt the actual data/plaintext
- **Asymmetric Encryption (RSA-OAEP)**: Used to encrypt the Initialization Vector (IV)

### Why Hybrid?

- **AES** is fast and efficient for encrypting large amounts of data
- **RSA** provides secure key exchange but is slower for large data
- By encrypting only the IV (16 bytes) with RSA, we get the benefits of both approaches

---

## Key Specifications

### AES Key
- **Algorithm**: AES-256
- **Key Size**: 256 bits (32 bytes)
- **Key Format**: Base64-encoded string or plain text
- **Example**: `"zKIcOJK5ui+0GMdehxBYpaTnYltfjBn0ug9BziV2Aq8="` (base64)
- **Key Handling**:
  - If key is < 32 bytes: Padded with zeros
  - If key is > 32 bytes: Truncated to 32 bytes
  - Accepts both base64-encoded and plain text keys

### RSA Keys
- **Key Size**: 2048 bits
- **Key Format**: PEM (Privacy-Enhanced Mail) format
- **Public Key Format**:
  ```
  -----BEGIN PUBLIC KEY-----
  [Base64 encoded key content]
  -----END PUBLIC KEY-----
  ```
- **Private Key Format**:
  ```
  -----BEGIN PRIVATE KEY-----
  [Base64 encoded key content]
  -----END PRIVATE KEY-----
  ```
- **Key Type**: PKCS#8 format

### Initialization Vector (IV)
- **Size**: 128 bits (16 bytes)
- **Generation**: Cryptographically secure random bytes
- **Purpose**: Ensures same plaintext produces different ciphertext each time
- **Encryption**: Encrypted using RSA-OAEP before transmission

---

## Algorithm Parameters

### AES-CBC Parameters
- **Algorithm**: AES-256-CBC
- **Key Length**: 256 bits (32 bytes)
- **Block Size**: 128 bits (16 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS7 (PKCS#7)
- **Character Encoding**: UTF-8

### RSA-OAEP Parameters
- **Algorithm**: RSA-OAEP (Optimal Asymmetric Encryption Padding)
- **Key Size**: 2048 bits
- **Padding**: OAEP
- **Hash Function**: SHA-1
- **Maximum Encryptable Size**: ~214 bytes (with 2048-bit key and SHA-1)
- **IV Encryption**: 16 bytes (well within limits)

---

## Key Formats

### AES Key Format

**Input Formats Accepted:**
1. **Base64 Encoded** (preferred):
   ```
   "zKIcOJK5ui+0GMdehxBYpaTnYltfjBn0ug9BziV2Aq8="
   ```
   - 44 characters (including padding)
   - Decoded to 32 bytes

2. **Plain Text**:
   ```
   "0123456789abcdef0123456789abcdef"
   ```
   - 32 characters (hex) or any text
   - Converted to bytes and normalized to 32 bytes

3. **Caesar Cipher Encrypted** (for encrypted keys):
   ```
   "34)56}78(9:;<defghi3456789:;<defghi"
   ```
   - Decrypted first using Caesar cipher (shift 3 or 7)
   - Then normalized to 32 bytes

### RSA Key Format (PEM)

**Public Key:**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv6AOLJ4s3nr9sEaw514b
[... base64 content ...]
CQIDAQAB
-----END PUBLIC KEY-----
```

**Private Key:**
```
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC/oA4snizeev2w
[... base64 content ...]
p6vtHJeVh5JlzUv98dGtHS4Qfw==
-----END PRIVATE KEY-----
```

**PEM Structure:**
- **Header**: `-----BEGIN [KEY TYPE]-----`
- **Content**: Base64 encoded DER (Distinguished Encoding Rules) format
- **Line Length**: 64 characters per line (standard)
- **Footer**: `-----END [KEY TYPE]-----`

**Encrypted PEM Keys (Caesar Cipher):**
- Headers encrypted: `-----ILNPU WbISPJ RLf-----` → `-----BEGIN PUBLIC KEY-----`
- Headers encrypted: `-----ILNPU WYPcHaL RLf-----` → `-----BEGIN PRIVATE KEY-----`
- Base64 content: Caesar shift 7 applied to alphanumeric characters only
- Special characters (+, /, =) preserved unchanged

---

## Node.js Implementation Details

### Technology Stack
- **Runtime**: Node.js
- **Crypto Library**: Built-in `crypto` module
- **Framework**: Express.js
- **Port**: 3000 (default)

### Key Files

#### 1. `utils/cryptoUtils.js`

**Functions:**

1. **`importAesKey(rawAesKey)`**
   - Input: String (base64 or plain text)
   - Output: Buffer (32 bytes)
   - Process:
     - Tries base64 decode first
     - Falls back to UTF-8 encoding
     - Normalizes to exactly 32 bytes (pad/truncate)

2. **`importPublicKey(rawPublicKey)`**
   - Input: PEM string
   - Output: `crypto.KeyObject`
   - Process:
     - Validates PEM headers
     - Formats to 64 characters per line
     - Uses `crypto.createPublicKey()`

3. **`importPrivateKey(rawPrivateKey)`**
   - Input: PEM string
   - Output: `crypto.KeyObject`
   - Process:
     - Validates PEM headers
     - Formats to 64 characters per line
     - Uses `crypto.createPrivateKey()`

4. **`encryptUsingAesKey(aesAlgorithm, aesKey, plaintext)`**
   - Algorithm: `aes-256-cbc`
   - Uses: `crypto.createCipheriv()`
   - Input encoding: UTF-8
   - Output: Buffer (encrypted data)

5. **`encryptUsingPublicKey(rsaAlgorithm, publicKey, iv)`**
   - Algorithm: RSA-OAEP
   - Padding: `RSA_PKCS1_OAEP_PADDING`
   - Hash: SHA-1 (from `rsaAlgorithm.hash`)
   - Uses: `crypto.publicEncrypt()`
   - Output: Buffer (encrypted IV)

6. **`decryptUsingPrivateKey(rsaAlgorithm, privateKey, encryptedIvBase64)`**
   - Algorithm: RSA-OAEP
   - Padding: `RSA_PKCS1_OAEP_PADDING`
   - Hash: SHA-1
   - Uses: `crypto.privateDecrypt()`
   - Input: Base64 string → Buffer
   - Output: Buffer (decrypted IV)

7. **`decryptUsingAesKey(aesAlgorithm, aesKey, encryptedDataBase64)`**
   - Algorithm: `aes-256-cbc`
   - Uses: `crypto.createDecipheriv()`
   - Input: Base64 string → Buffer
   - Output: Buffer (decrypted data)

8. **`arrayBufferToBase64String(buffer)`**
   - Converts Buffer to Base64 string
   - Uses: `buffer.toString('base64')`

#### 2. `services/encryptionService.js`

**Function: `hybridEncryption(plaintextData, rawPublicKey, rawAesKey)`**

**Steps:**

1. **Algorithm Configuration:**
   ```javascript
   rsaAlgorithm = {
     name: 'RSA-OAEP',
     hash: 'SHA-1'
   }
   aesAlgorithm = {
     name: 'AES-CBC'
   }
   ```

2. **Key Decryption (if needed):**
   - Checks if AES key is base64 or needs Caesar decryption
   - Checks if RSA key has PEM headers or needs decryption
   - Decrypts keys using `modifiedCaesarDecrypt()` or `keyDecrypt()`

3. **Key Import:**
   - Imports AES key: `importAesKey(decryptedAesKey)` → 32-byte Buffer
   - Imports RSA public key: `importPublicKey(decryptedPublicKey)` → KeyObject

4. **IV Generation:**
   - Generates random 16 bytes: `crypto.randomBytes(16)`
   - Assigns to: `aesAlgorithm.iv`

5. **Data Preparation:**
   - Converts plaintext to string (if object: `JSON.stringify()`)
   - URI encodes: `encodeURIComponent(plaintextString)`

6. **Parallel Encryption:**
   ```javascript
   Promise.all([
     encryptUsingAesKey(aesAlgorithm, importedAesKey, encodedPlaintext),
     encryptUsingPublicKey(rsaAlgorithm, importedPublicKey, aesAlgorithm.iv)
   ])
   ```
   - Encrypts data with AES-CBC
   - Encrypts IV with RSA-OAEP
   - Both execute in parallel for performance

7. **Base64 Encoding:**
   - Converts both encrypted buffers to Base64 strings
   - Returns JSON:
     ```json
     {
       "encryptedDataBase64": "...",
       "encryptedIvBase64": "..."
     }
     ```

#### 3. `services/decryptionService.js`

**Function: `hybridDecryption(encObject, rawPrivateKey, rawAesKey)`**

**Steps:**

1. **Algorithm Configuration:**
   ```javascript
   rsaAlgorithm = { name: 'RSA-OAEP', hash: 'SHA-1' }
   aesAlgorithm = { name: 'AES-CBC' }
   ```

2. **Key Decryption & Import:**
   - Decrypts keys if encrypted (Caesar cipher)
   - Imports AES key (32 bytes)
   - Imports RSA private key (KeyObject)

3. **IV Decryption:**
   - Base64 decodes: `encryptedIvBase64`
   - Decrypts using RSA-OAEP: `decryptUsingPrivateKey()`
   - Output: 16-byte IV Buffer
   - Assigns to: `aesAlgorithm.iv`

4. **Data Decryption:**
   - Base64 decodes: `encryptedDataBase64`
   - Decrypts using AES-CBC with decrypted IV
   - Output: Decrypted data Buffer

5. **Data Processing:**
   - UTF-8 decodes Buffer to string
   - URI decodes: `decodeURIComponent()`
   - Attempts JSON parse (falls back to string if not JSON)
   - Returns: JavaScript object or string

---

## Flutter Implementation Details

### Technology Stack
- **Framework**: Flutter/Dart
- **Crypto Library**: `pointycastle` package
- **Version**: pointycastle ^3.7.3 or ^3.9.1

### Key Files

#### 1. `lib/utils/crypto_utils.dart`

**Functions:**

1. **`importAesKey(String rawAesKey)`**
   - Input: String (base64 or plain text)
   - Output: `Uint8List` (32 bytes)
   - Process:
     - Tries `base64Decode()` first
     - Falls back to `utf8.encode()`
     - Normalizes to exactly 32 bytes using `Uint8List`

2. **`importPublicKey(String rawPublicKey)`**
   - Input: PEM string
   - Output: `RSAPublicKey` (from pointycastle)
   - Process:
     - Extracts base64 content from PEM
     - Formats to proper PEM structure
     - Uses custom `parseRSAPublicKeyFromPEM()` function
     - Parses ASN.1 DER format

3. **`importPrivateKey(String rawPrivateKey)`**
   - Input: PEM string
   - Output: `RSAPrivateKey` (from pointycastle)
   - Process:
     - Validates PEM headers
     - Uses custom `parseRSAPrivateKeyFromPEM()` function
     - Parses ASN.1 structure (PKCS#8 or PKCS#1)

4. **`encryptUsingAesKey(Uint8List iv, Uint8List aesKey, String plaintext)`**
   - Uses: `PaddedBlockCipher` with `'AES/CBC/PKCS7'`
   - Parameters:
     - `KeyParameter(aesKey)` - 32 bytes
     - `ParametersWithIV(key, iv)` - 16-byte IV
   - Plaintext: UTF-8 encoded bytes
   - Output: `Uint8List` (encrypted data)

5. **`encryptUsingPublicKey(RSAPublicKey publicKey, Uint8List iv)`**
   - Uses: `OAEPEncoding(RSAEngine())`
   - Hash: SHA-1 (default in pointycastle)
   - Padding: OAEP
   - Initialization: `PublicKeyParameter<RSAPublicKey>(publicKey)`
   - Output: `Uint8List` (encrypted IV, typically 256 bytes for 2048-bit RSA)

6. **`decryptUsingPrivateKey(RSAPrivateKey privateKey, String encryptedIvBase64)`**
   - Base64 decodes input
   - Uses: `OAEPEncoding(RSAEngine())`
   - Initialization: `PrivateKeyParameter<RSAPrivateKey>(privateKey)`
   - Output: `Uint8List` (16-byte decrypted IV)

7. **`decryptUsingAesKey(Uint8List iv, Uint8List aesKey, String encryptedDataBase64)`**
   - Base64 decodes input
   - Uses: `PaddedBlockCipher('AES/CBC/PKCS7')`
   - Parameters: IV + AES key
   - Output: `Uint8List` (decrypted data)

8. **`generateRandomBytes(int length)`**
   - Uses: `Random.secure()` (cryptographically secure)
   - Output: `Uint8List` of specified length

9. **`arrayBufferToBase64String(Uint8List buffer)`**
   - Uses: `base64Encode()` from `dart:convert`
   - Output: Base64 string

#### 2. `lib/services/encryption_service.dart`

**Function: `hybridEncryption(plaintextData, rawPublicKey, rawAesKey)`**

**Steps:**

1. **Key Decryption & Import:**
   - Checks if keys are encrypted (Caesar cipher)
   - Decrypts if needed using `modifiedCaesarDecrypt()` or `keyDecrypt()`
   - Imports AES key (32 bytes)
   - Imports RSA public key

2. **IV Generation:**
   - Generates 16 random bytes: `generateRandomBytes(16)`
   - Returns: `Uint8List` (16 bytes)

3. **Data Preparation:**
   - Converts to string (if Map/List: `jsonEncode()`)
   - URI encodes: `Uri.encodeComponent()`

4. **Encryption:**
   - Encrypts data: `encryptUsingAesKey(iv, importedAesKey, encodedPlaintext)`
   - Encrypts IV: `encryptUsingPublicKey(importedPublicKey, iv)`
   - Both return `Uint8List`

5. **Base64 Encoding:**
   - Converts both to Base64 strings
   - Returns: `Map<String, String>`
     ```dart
     {
       'encryptedDataBase64': '...',
       'encryptedIvBase64': '...'
     }
     ```

**Function: `hybridDecryption(encObject, rawPrivateKey, rawAesKey)`**

**Steps:**

1. **Key Decryption & Import:**
   - Decrypts keys if encrypted
   - Imports AES key and RSA private key

2. **IV Decryption:**
   - Base64 decodes `encryptedIvBase64`
   - Decrypts with RSA-OAEP: `decryptUsingPrivateKey()`
   - Returns 16-byte `Uint8List` (IV)

3. **Data Decryption:**
   - Base64 decodes `encryptedDataBase64`
   - Decrypts with AES-CBC: `decryptUsingAesKey(iv, importedAesKey, ...)`
   - Returns `Uint8List` (decrypted data)

4. **Data Processing:**
   - UTF-8 decodes: `utf8.decode()`
   - URI decodes: `Uri.decodeComponent()`
   - Attempts JSON parse: `jsonDecode()` (falls back to string)
   - Returns: `dynamic` (object or string)

#### 3. RSA Key Parsing (`lib/utils/rsa_key_parser.dart`)

**Custom ASN.1 Parser:**

- Parses PEM format RSA keys
- Handles both PKCS#1 and PKCS#8 formats
- Extracts modulus, public exponent, private exponent, p, q values
- Constructs `RSAPublicKey` or `RSAPrivateKey` objects

---

## Complete Encryption Flow

### Step-by-Step Process

#### 1. **Input Preparation**
```
Input: "Hello, World!" (or any data)
```

#### 2. **Key Loading**
```
AES Key: "zKIcOJK5ui+0GMdehxBYpaTnYltfjBn0ug9BziV2Aq8=" (base64)
RSA Public Key: PEM format string
```

#### 3. **Key Processing**
- AES Key: Base64 decoded → 32 bytes (256 bits)
- RSA Public Key: PEM parsed → KeyObject/RSAPublicKey

#### 4. **IV Generation**
```
IV = Random 16 bytes (128 bits)
Example: [0x12, 0x34, 0x56, ..., 0xEF] (16 bytes)
```

#### 5. **Data Encoding**
```
Plaintext: "Hello, World!"
→ JSON (if object): {"data": "Hello, World!"}
→ URI Encode: "Hello%2C%20World%21"
→ UTF-8 Bytes: [0x48, 0x65, 0x6C, ...]
```

#### 6. **AES Encryption**
```
Algorithm: AES-256-CBC
Input: UTF-8 bytes of URI-encoded plaintext
Key: 32-byte AES key
IV: 16-byte random IV
Output: Encrypted data (variable length, multiple of 16 bytes due to padding)
```

#### 7. **IV Encryption**
```
Algorithm: RSA-OAEP (SHA-1)
Input: 16-byte IV
Public Key: 2048-bit RSA public key
Output: 256-byte encrypted IV (2048 bits / 8 = 256 bytes)
```

#### 8. **Base64 Encoding**
```
Encrypted Data → Base64: "Lpd85zcz/ietRrWywjF9P2AgWsHeBPtTntZRI/aOhRgcGhPcWv6nEG93WA2aYaa0"
Encrypted IV → Base64: "VcWD+HmM7mI91laoag+OD4BW0+2sO8z1i7Ck4AL6X8El8fnbor5JL5SCqmQnms4AH..."
```

#### 9. **Output**
```json
{
  "encryptedDataBase64": "Lpd85zcz/ietRrWywjF9P2AgWsHeBPtTntZRI/aOhRgcGhPcWv6nEG93WA2aYaa0",
  "encryptedIvBase64": "VcWD+HmM7mI91laoag+OD4BW0+2sO8z1i7Ck4AL6X8El8fnbor5JL5SCqmQnms4AH..."
}
```

### Visual Flow Diagram

```
┌─────────────┐
│  Plaintext  │
│ "Hello..."  │
└──────┬──────┘
       │
       ├──→ [JSON Stringify] → [URI Encode] → [UTF-8 Bytes]
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    AES-256-CBC Encryption                    │
│  Key: 32 bytes (256 bits)                                   │
│  IV: 16 bytes (random, generated)                           │
│  Mode: CBC                                                   │
│  Padding: PKCS7                                              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Encrypted Data  │
              │  (Variable len) │
              └────────┬────────┘
                       │
                       ├──→ [Base64 Encode]
                       │
                       ▼
              ┌──────────────────────┐
              │ encryptedDataBase64  │
              └──────────────────────┘
                       
┌─────────────┐
│      IV     │
│  16 bytes   │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                   RSA-OAEP Encryption                        │
│  Public Key: 2048-bit RSA                                    │
│  Hash: SHA-1                                                 │
│  Padding: OAEP                                               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Encrypted IV    │
              │   256 bytes     │
              └────────┬────────┘
                       │
                       ├──→ [Base64 Encode]
                       │
                       ▼
              ┌──────────────────────┐
              │ encryptedIvBase64    │
              └──────────────────────┘
```

---

## Complete Decryption Flow

### Step-by-Step Process

#### 1. **Input**
```json
{
  "encryptedDataBase64": "Lpd85zcz/ietRrWywjF9P2AgWsHeBPtTntZRI/aOhRgcGhPcWv6nEG93WA2aYaa0",
  "encryptedIvBase64": "VcWD+HmM7mI91laoag+OD4BW0+2sO8z1i7Ck4AL6X8El8fnbor5JL5SCqmQnms4AH..."
}
```

#### 2. **Key Loading**
```
AES Key: Same as encryption (32 bytes)
RSA Private Key: PEM format string
```

#### 3. **Key Processing**
- AES Key: Base64 decoded → 32 bytes
- RSA Private Key: PEM parsed → KeyObject/RSAPrivateKey

#### 4. **IV Decryption**
```
Input: encryptedIvBase64 (base64 string)
→ Base64 Decode: 256-byte encrypted IV
→ RSA-OAEP Decrypt: Using private key
→ Output: 16-byte IV (original)
```

#### 5. **Data Decryption**
```
Input: encryptedDataBase64 (base64 string)
→ Base64 Decode: Encrypted data bytes
→ AES-256-CBC Decrypt: Using AES key + decrypted IV
→ Output: Decrypted data bytes (UTF-8)
```

#### 6. **Data Processing**
```
Decrypted Bytes → UTF-8 Decode → "Hello%2C%20World%21"
→ URI Decode → "Hello, World!"
→ JSON Parse (if valid JSON) → Object
→ Return: Object or String
```

### Visual Flow Diagram

```
┌──────────────────────┐
│ encryptedIvBase64    │
└──────┬───────────────┘
       │
       ├──→ [Base64 Decode] → 256 bytes
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                  RSA-OAEP Decryption                         │
│  Private Key: 2048-bit RSA                                   │
│  Hash: SHA-1                                                 │
│  Padding: OAEP                                               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   IV (16 bytes) │
              └────────┬────────┘
                       │
                       │ (Used in AES decryption)
                       │
┌──────────────────────┐
│ encryptedDataBase64  │
└──────┬───────────────┘
       │
       ├──→ [Base64 Decode] → Variable length bytes
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                  AES-256-CBC Decryption                      │
│  Key: 32 bytes (256 bits)                                   │
│  IV: 16 bytes (from RSA decryption above)                   │
│  Mode: CBC                                                   │
│  Padding: PKCS7 (removed automatically)                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Decrypted Bytes │
              │    (UTF-8)      │
              └────────┬────────┘
                       │
                       ├──→ [UTF-8 Decode] → "Hello%2C%20World%21"
                       │
                       ├──→ [URI Decode] → "Hello, World!"
                       │
                       ├──→ [JSON Parse] → Object (if valid JSON)
                       │
                       ▼
              ┌─────────────────┐
              │   Plaintext     │
              │ "Hello, World!" │
              └─────────────────┘
```

---

## Data Formats & Encoding

### Input Data Formats

1. **Plaintext**:
   - String: `"Hello, World!"`
   - Number: `12345`
   - Object: `{"name": "John", "age": 30}`
   - Array: `[1, 2, 3, 4, 5]`

2. **Encoding Process**:
   ```
   Object/Array → JSON.stringify() → String
   String → encodeURIComponent() → URI-encoded String
   URI String → UTF-8 Encoding → Bytes (Uint8List/Buffer)
   ```

### Output Data Formats

1. **Encrypted Output**:
   ```json
   {
     "encryptedDataBase64": "Base64 string (variable length)",
     "encryptedIvBase64": "Base64 string (344 characters for 256 bytes)"
   }
   ```

2. **Base64 Encoding Details**:
   - Input: Binary data (bytes)
   - Output: ASCII string (A-Z, a-z, 0-9, +, /, =)
   - Padding: `=` characters for alignment
   - Example: 16 bytes → 24 Base64 characters
   - Example: 256 bytes → 344 Base64 characters

3. **Decrypted Output**:
   - Attempts JSON parse first
   - Falls back to plain string if not valid JSON
   - Returns original data type (object, array, string, number)

### Character Encoding

- **Internal**: UTF-8 (8-bit Unicode Transformation Format)
- **URI Encoding**: Uses `encodeURIComponent()` / `Uri.encodeComponent()`
- **Special Characters**: Encoded as `%XX` format (e.g., space → `%20`)

### Byte Array Formats

**Node.js:**
- Uses `Buffer` objects
- Immutable byte arrays
- Methods: `Buffer.from()`, `buffer.toString('base64')`

**Flutter:**
- Uses `Uint8List` objects
- Typed list of 8-bit unsigned integers
- Methods: `Uint8List.fromList()`, `base64Encode()`

---

## Code Structure

### Node.js Project Structure

```
aes-poc/
├── server.js                    # Express server, API endpoints
├── services/
│   ├── encryptionService.js     # hybridEncryption() function
│   └── decryptionService.js     # hybridDecryption() function
├── utils/
│   ├── cryptoUtils.js           # Low-level crypto operations
│   └── keyDecrypt.js            # Caesar cipher key decryption
└── package.json                 # Dependencies
```

**Key Dependencies:**
- `express`: ^4.18.2 (Web framework)
- `cors`: ^2.8.5 (CORS middleware)
- Built-in `crypto`: Node.js crypto module

### Flutter Project Structure

```
sample_aes_flutter/
├── lib/
│   ├── main.dart                # UI, user interface
│   ├── services/
│   │   ├── encryption_service.dart      # hybridEncryption(), hybridDecryption()
│   │   └── encryption_api_service.dart  # HTTP API client
│   └── utils/
│       ├── crypto_utils.dart            # Low-level crypto operations
│       ├── rsa_key_parser.dart          # RSA key parsing (ASN.1)
│       ├── key_decrypt.dart             # Caesar cipher key decryption
│       └── test_keys.dart               # Test keys
└── pubspec.yaml                 # Dependencies
```

**Key Dependencies:**
- `http`: ^1.1.0 (HTTP client)
- `pointycastle`: ^3.7.3 (Cryptography library)
- `crypto`: ^3.0.3 (Dart crypto utilities)

---

## Security Considerations

### Algorithm Security

1. **AES-256**:
   - Industry standard, approved for top-secret data
   - 256-bit key provides 2^256 possible keys
   - Considered secure against brute force attacks

2. **RSA-2048**:
   - 2048-bit keys are currently secure
   - Recommended minimum until 2030
   - OAEP padding prevents certain attacks

3. **SHA-1**:
   - Note: SHA-1 is considered weak for signatures
   - However, for OAEP padding in RSA, SHA-1 is still acceptable
   - For future-proofing, consider upgrading to SHA-256

### Key Management

1. **Key Storage**:
   - Keys should be stored securely (environment variables, key vaults)
   - Never commit keys to version control
   - Use encrypted keys with proper decryption mechanisms

2. **Key Rotation**:
   - Implement key rotation policies
   - Support multiple key versions during transition

3. **Key Distribution**:
   - Use secure channels for key exchange
   - Consider using key exchange protocols (e.g., ECDH)

### Best Practices

1. **IV Generation**:
   - Always use cryptographically secure random number generators
   - Never reuse IVs with the same key
   - Generate fresh IV for each encryption

2. **Error Handling**:
   - Never expose sensitive information in error messages
   - Log errors securely without key material

3. **Transport Security**:
   - Use HTTPS/TLS for API communication
   - Validate SSL certificates

4. **Input Validation**:
   - Validate all inputs before processing
   - Sanitize data to prevent injection attacks

---

## Performance Characteristics

### Encryption Speed

- **AES-256-CBC**: ~200-500 MB/s (depending on hardware)
- **RSA-OAEP (2048-bit)**: ~100-500 operations/second
- **Hybrid Approach**: Combines speed of AES with security of RSA

### Data Size Impact

- **Plaintext**: Variable size
- **Encrypted Data**: Plaintext size + padding (multiple of 16 bytes)
- **Encrypted IV**: Always 256 bytes (2048 bits / 8)
- **Total Overhead**: ~256 bytes + padding (min 16 bytes) = ~272 bytes minimum

### Example Sizes

| Plaintext Size | Encrypted Data | Encrypted IV | Total Size | Overhead |
|----------------|----------------|--------------|------------|----------|
| 10 bytes       | 16 bytes       | 256 bytes    | 272 bytes  | 262 bytes (2620%) |
| 100 bytes      | 112 bytes      | 256 bytes    | 368 bytes  | 268 bytes (268%) |
| 1 KB           | 1024 bytes     | 256 bytes    | 1280 bytes | 256 bytes (25%) |
| 10 KB          | 10240 bytes    | 256 bytes    | 10496 bytes| 256 bytes (2.5%) |

---

## Testing & Validation

### Test Keys

Both implementations include test keys for development:

**AES Key (Base64):**
```
"zKIcOJK5ui+0GMdehxBYpaTnYltfjBn0ug9BziV2Aq8="
```

**RSA Public Key:**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
```

**RSA Private Key:**
```
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC...
-----END PRIVATE KEY-----
```

### Test Scenarios

1. **Round-trip Encryption/Decryption**:
   - Encrypt plaintext
   - Decrypt encrypted data
   - Verify original plaintext matches

2. **Cross-platform Compatibility**:
   - Encrypt in Node.js, decrypt in Flutter
   - Encrypt in Flutter, decrypt in Node.js
   - Verify both directions work

3. **Edge Cases**:
   - Empty strings
   - Special characters
   - Unicode characters
   - Large data (1MB+)
   - JSON objects/arrays

---

## API Endpoints

### Node.js Server Endpoints

**Base URL**: `http://localhost:3000`

1. **GET /health**
   - Health check endpoint
   - Returns: `{"status": "ok", "message": "..."}`

2. **GET /api/keys**
   - Returns default keys (testing only)
   - Returns: `{publicKey, privateKey, aesKey}`

3. **POST /api/encrypt**
   - Request: `{plaintextData, rawPublicKey?, rawAesKey?}`
   - Response: `{success: true, encryptedData: {...}}`

4. **POST /api/decrypt**
   - Request: `{encryptedData: {...}, rawPrivateKey?, rawAesKey?}`
   - Response: `{success: true, encryptedData: {...}}`

---

## Troubleshooting

### Common Issues

1. **Key Format Errors**:
   - Ensure PEM keys have proper headers/footers
   - Check for line breaks (64 chars per line)
   - Verify base64 encoding is correct

2. **Decryption Failures**:
   - Keys must match between encryption and decryption
   - IV must be correctly decrypted first
   - Check for data corruption during transmission

3. **Size Limits**:
   - RSA-OAEP can encrypt max ~214 bytes with 2048-bit key + SHA-1
   - IV (16 bytes) is well within limits
   - Large data should use AES only

4. **Encoding Issues**:
   - Ensure consistent UTF-8 encoding
   - Check URI encoding/decoding is applied correctly
   - Verify JSON parsing/stringification

---

## Version History

- **Current Version**: 1.0.0
- **Node.js**: Uses built-in crypto module
- **Flutter**: Uses pointycastle ^3.7.3
- **Compatibility**: Node.js 14+, Flutter 3.0+

---

## References

1. **AES Specification**: FIPS 197 (Advanced Encryption Standard)
2. **RSA Specification**: PKCS#1 v2.2 (RSA Cryptography Standard)
3. **OAEP Specification**: RFC 3447 (Public-Key Cryptography Standards)
4. **PEM Format**: RFC 1421 (Privacy Enhancement for Internet Electronic Mail)
5. **Base64 Encoding**: RFC 4648 (The Base16, Base32, and Base64 Data Encodings)

---

## Conclusion

This hybrid encryption system provides:
- **Security**: Strong encryption with AES-256 and RSA-2048
- **Performance**: Fast bulk data encryption with AES
- **Flexibility**: Secure key exchange with RSA
- **Compatibility**: Works across Node.js and Flutter platforms

The implementation follows industry standards and best practices for cryptographic operations.

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Maintained By**: Development Team

