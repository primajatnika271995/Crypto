# iOSCrypto
This is an iOS crypto library.
## Implement a symmetric cipher

```swift
let alghrithm: SymmetryCipher.Algorithm = .aes
let data = "Hello world".data(using: .utf8)!
let key = try alghrithm.generateRandomKey()
let iv = alghrithm.generateRandomIV()
let cipher = try SymmetryCipher(algorithm: alghrithm, key: key, iv: iv, padding: .pkcs7, mode: .cbc)
let encrypted = try cipher.process(.encrypt, data: data)
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
