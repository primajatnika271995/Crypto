# iOSCrypto
This is an iOS crypto library.
## Implement a symmetric cipher

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

## Supported symmetric algorithms
* AES
* DES
* Tripple DES
* Cast
* RC4
* RC2
* Blowfish
