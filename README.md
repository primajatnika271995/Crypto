# iOSCrypto
This is a iOS crypto library. It supports following functions:
- [x] Symmetry Cipher
- [ ] Asymmetry Cipher
- [ ] Hashing function
## Symmetry Cipher
### Implement a Symmetric Cipher

```swift
let alghrithm: SymmetryCipher.Algorithm = .aes
let data = "Hello world".data(using: .utf8)!
// Generate random key
let key = try alghrithm.generateRandomKey()
// Generate random IV
let iv = alghrithm.generateRandomIV()
let cipher = try SymmetryCipher(algorithm: alghrithm, key: key, iv: iv)
// Encrypt data
let encrypted = try cipher.process(.encrypt, data: data)
// Decrypt data
let decrypted = try cipher.process(.decrypt, data: encrypted)
```
You can also speciafy **padding** and **mode**, use `encrypt` and `decrypt` method:
```swift
let alghrithm: SymmetryCipher.Algorithm = .aes
let data = "Hello world".data(using: .utf8)!
let key = try alghrithm.generateRandomKey()
let iv = alghrithm.generateRandomIV()
let cipher = try SymmetryCipher(algorithm: alghrithm, key: key, iv: iv, padding: .pkcs7, mode: .cbc)
// Encrypt data
let encrypted = try cipher.encrypt(data: data)
// Decrypt data
let decrypted = try cipher.decrypt(data: encrypted)
```

### Supported Symmetric algorithms
* AES
* DES
* Tripple DES
* Cast
* RC4
* RC2
* Blowfish

### Supported modes

* ECB
* CBC
* CFB
* CTR
* OFB
* RC4
* CFB8

### Supported paddings
* NoPadding
* PKCS7Padding

### Check whether an algorithm supports certain mode and padding
```swift
print(SymmetryCipher.Algorithm.aes.isValid(mode: .ctr, padding: .pkcs7))
```
### Check whether we need IV parameter in certain mode
```swift
print(SymmetryCipher.Mode.cbc.needesIV())
// prints true
print(SymmetryCipher.Mode.ecb.needesIV())
// prints false
```
