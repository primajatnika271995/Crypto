# Crypto
This is a swift crypto library. It’s made to be convenient to use and support as many crypto methods as possible. It supports following functions:
- [x] Symmetric Cipher
- [x] Digest
- [x] HMAC
- [x] Convenience methods
- [ ] Asymmetric Cipher

## Integration
It's very easy to integrate, you just need Swift Package Manager, which is already installed with XCode. In Xcode, you can choose File->Swift Packages->Add Pakcage dependancies, and add https://github.com/LoniQin/Crypto.
## Symmetric Cipher
### How to use

```swift
do {
    let data = try "I am fine".data(.utf8)
    let key = try "1111111111111111".data(.ascii)
    let iv = try "1111111111111111".data(.ascii)
    let cipher = SymmetricCipher(.aes, key: key, iv: iv)
    // Encrypt data
    let encrypted = try cipher.encrypt(data)
    // Decrypt data
    let decrypted = try cipher.decrypt(encrypted)
    print(try encrypted.string(.base64))
    print(try decrypted.string(.utf8))
} catch let error {
    print(error)
}
```

Or:

```swift
import Crypto

do {
    let plainText = "I am fine"
    var key = "1111111111111111"
    var iv = "1111111111111111"
    // AES
    print(try plainText.process(.aes(.encrypt, key: key, iv: iv)))
    iv = "11111111"
    // RC2
    print(try plainText.process(.rc2(.encrypt, key: key, iv: iv)))
    // CAST
    print(try plainText.process(.cast(.encrypt, key: key, iv: iv)))
    // BLOWFISH
    print(try plainText.process(.blowfish(.encrypt, key: key, iv: iv)))
    // Tripple DES
    key = "111111111111111111111111"
    print(try plainText.process(.des3(.encrypt, key: key, iv: iv)))
    // RC4
    print(try plainText.process(.rc4(.encrypt, key: key, iv: iv)))
} catch let error {
    print(error)
}
```

### Iterate possible combinations
Now I iterate combinations of algorithms and modes with following code:
```swift
import Crypto

do {
    let plainText = "Hello world"
    print("Plain text: \(plainText)")
    print("-----------------------------------------------------")
    for algorithm in SymmetricCipher.Algorithm.allCases {
        for mode in SymmetricCipher.Mode.allCases {
            let key = try algorithm.generateRandomKey()
            let iv = mode.needesIV() ? algorithm.generateRandomIV() : Data()
            let cipher = SymmetricCipher(algorithm, key: key, iv: iv, mode: mode)
            if cipher.isValid {
                let data = plainText.data(using: .utf8)!
                let encrypted = try cipher.process(.encrypt, data)
                print("Algorithm: \(String(describing: algorithm).uppercased())")
                print("Mode: \(String(describing: mode).uppercased())")
                print("key: \(key.hex)")
                if mode.needesIV() {
                    print("iv: \(iv.hex)")
                }
                print("Cipher text: \(encrypted.hex)")
                let decrypted = try cipher.process(.decrypt, encrypted)
                print("-----------------------------------------------------")
            }
        }
    }
} catch let error {
    print("Error:\(error)")
}
/*
Plain text: Hello world
-----------------------------------------------------
Algorithm: AES
Mode: ECB
key: 4d992cdf76296a11f3c06f2f2af195de6d2af4b28e031139
Cipher text: a348177ed2f96da2f8ac96dc9dc6846c
-----------------------------------------------------
Algorithm: AES
Mode: CBC
key: fc085bae49c92087ffc31aec26c8b3aeee0a8fb9daf5583b
iv: 340d35798f0a53bf86d95bc96e118a83
Cipher text: 3e0f8bb3a6e6a7787f944f2276003688
-----------------------------------------------------
Algorithm: AES
Mode: CFB
key: 7a54627df1b3b9bad754393b3a55d1f6384bdcc4bbf186e0
iv: 0fd4b19136d1e8cc58ad694519a037e3
Cipher text: 7a633a7ada898471120dde
-----------------------------------------------------
Algorithm: AES
Mode: CTR
key: f2aba580516b652f68ef4e4da912664b34b7aacc8682d355
iv: 8ac347d99fe820f75a7de7e5e2f12b4e
Cipher text: ca9cccc2eb901827baf21d
-----------------------------------------------------
Algorithm: AES
Mode: OFB
key: 83ad872fe7828126b3cd74c968ae5b9716cd92e5d413c1df
iv: ebbbe10615a0da49754b5a0d56507f65
Cipher text: 8ded1a3670773bf0a20f31
-----------------------------------------------------
Algorithm: AES
Mode: CFB8
key: b92f55c77f9868e68ff70219bbcf6c4a0df47dda75130289
iv: 49fd12e73ef23cfe40bf509f93a2ef05
Cipher text: 5e489e2e2a198c61dc1fa8
-----------------------------------------------------
Algorithm: DES
Mode: ECB
key: 3a3643592bd9d2e4
Cipher text: 404acc5da2ae2517599ca47c5c960903
-----------------------------------------------------
Algorithm: DES
Mode: CBC
key: cd8093d1b37a4a93
iv: fa989bf4cd6dbce2
Cipher text: 325079b69f2012643802568c73d8ecf9
-----------------------------------------------------
Algorithm: DES
Mode: CFB
key: bdf530051b8ec87d
iv: fb6a1df23630c0a4
Cipher text: 78cc623ada8d1212e1c0dc
-----------------------------------------------------
Algorithm: DES
Mode: CTR
key: 2e90421b2ddc2532
iv: 7955cd4a86f8b06d
Cipher text: e9f8d127d1d3ad09d73da0
-----------------------------------------------------
Algorithm: DES
Mode: OFB
key: f105186bed0ffb46
iv: cf303af23df1cf5d
Cipher text: 727b264dcb6e7ae5680730
-----------------------------------------------------
Algorithm: DES
Mode: CFB8
key: 98a3512234ebd41d
iv: a1ec192dc2e243fd
Cipher text: 0f340713b739e12282fbfe
-----------------------------------------------------
Algorithm: DES3
Mode: ECB
key: 428ebaade12a0bc141f837c55dc995a98f9600c8b7ceb919
Cipher text: b86ae0b73c2c68dc9ad9766081c122ec
-----------------------------------------------------
Algorithm: DES3
Mode: CBC
key: 0397a2b96055fe087bfaffd09f195798fd9091a12d8d8e65
iv: 0d92ff84499b876a
Cipher text: 619937209fa0047ba9a5acbcb1995fe8
-----------------------------------------------------
Algorithm: DES3
Mode: CFB
key: ae485ed6af7c518da5890a4c3c6c5b8fe6b33a15ac55b574
iv: f039e5c1dacc2a83
Cipher text: 57fe5bcd47c4f483b421e1
-----------------------------------------------------
Algorithm: DES3
Mode: CTR
key: 9aa41fe97f3dc5c99d456a6025e4ac879ae17866d3b98df0
iv: 2984597320d695f6
Cipher text: 0f260d4a8801044ebf0b64
-----------------------------------------------------
Algorithm: DES3
Mode: OFB
key: b413d2692716e904fa94c962a8d3940bc71d7df87b5b085b
iv: 2a2020c15704f6fb
Cipher text: 6a8a33c664049f5c0716ca
-----------------------------------------------------
Algorithm: DES3
Mode: CFB8
key: 60c49172c12c1d42c59daa98a9d01dc9552699d2c4fdc869
iv: 2f124c1ec19adaf5
Cipher text: 57fe5790785efbe6288fb9
-----------------------------------------------------
Algorithm: CAST
Mode: ECB
key: 63ccd1fe86ad6815
Cipher text: d82d6fd0d9dddda1540711b098efef4c
-----------------------------------------------------
Algorithm: CAST
Mode: CBC
key: 7cdc8926804f9d2d
iv: ab275c13e470ffa6
Cipher text: c1cd635d2549a87cb01b2db16d532cb5
-----------------------------------------------------
Algorithm: CAST
Mode: CFB
key: 4d2e8cc6b397dcbe
iv: 99709d74bd99a425
Cipher text: 53698bd420b73e784a7640
-----------------------------------------------------
Algorithm: CAST
Mode: CTR
key: d933c3e609023732
iv: f240de08d869850a
Cipher text: 5cf465c9ff4663b1156f1e
-----------------------------------------------------
Algorithm: CAST
Mode: OFB
key: 5a3a1109a32224b2
iv: f4eb2a9d66b5f825
Cipher text: c14debd0c3e28210651949
-----------------------------------------------------
Algorithm: CAST
Mode: CFB8
key: 374f22bfc88dc9bb
iv: 46bb46f8104c1be2
Cipher text: cd0796583123e8ffe69ade
-----------------------------------------------------
Algorithm: RC4
Mode: RC4
key: ca9cc68032186c3b
iv: 65d276af3e668e23
Cipher text: 90a9f22146b3eb0b71dadd
-----------------------------------------------------
Algorithm: RC2
Mode: ECB
key: f1ddc2f3f95d952b
Cipher text: f0c7dad6c87674022b50ba5210762419
-----------------------------------------------------
Algorithm: RC2
Mode: CBC
key: d188d566477e93dc
iv: 90dd22e5001dcf92
Cipher text: 9beb0dd8635790c365f9fd606a3800fd
-----------------------------------------------------
Algorithm: RC2
Mode: CFB
key: 57e9a7b3b622820d
iv: 64ecc68304a1b7f1
Cipher text: 826320084b03d4c0568e39
-----------------------------------------------------
Algorithm: RC2
Mode: CTR
key: f8fc289d0140f58a
iv: 4f9fd9838e8a8146
Cipher text: 5321651da3383e78bb4c44
-----------------------------------------------------
Algorithm: RC2
Mode: OFB
key: 8deef6a79fed8d44
iv: e390d7d401b730f8
Cipher text: 62e03414db2512c764e7c2
-----------------------------------------------------
Algorithm: RC2
Mode: CFB8
key: 7ce4db22505ac35e
iv: 818808ce55f1f1ff
Cipher text: 8872d97d8a7817cba5ea32
-----------------------------------------------------
Algorithm: BLOWFISH
Mode: ECB
key: b746ca608990a925
Cipher text: 57605d4b88a5cab5c3780fe2e8aea38d
-----------------------------------------------------
Algorithm: BLOWFISH
Mode: CBC
key: 1461b599b6e35bce
iv: 2427d1f8ee000c7b
Cipher text: 8e03a61aaf5e66464d4dc82e44a6858c
-----------------------------------------------------
Algorithm: BLOWFISH
Mode: CFB
key: da380b343d520e4d
iv: a2b8e8f6c60fe08b
Cipher text: 4e47af9036c0163d81cfba
-----------------------------------------------------
Algorithm: BLOWFISH
Mode: CTR
key: d6c0ed86f77c589d
iv: 28ba065d5b44b2a1
Cipher text: 8f643839e271f0f3b7475c
-----------------------------------------------------
Algorithm: BLOWFISH
Mode: OFB
key: cb47e18f2a2285dd
iv: a5a5d1a12cf78303
Cipher text: 63777f0c4ccab413ea39d5
-----------------------------------------------------
Algorithm: BLOWFISH
Mode: CFB8
key: 61f1c0d35a420070
iv: 7630adb075b68a52
Cipher text: 9de4f17afe83fa720ae781
-----------------------------------------------------
*/
```


### Supported Algorithms
* AES
* DES
* Tripple DES
* Cast
* RC4
* RC2
* Blowfish

### Supported Cipher Modes

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

There are some exceptions: RC4 algorithm only supports RC4 Cipher Mode, other algorithms can’t use RC4 mode. And ECB mode and CBC mode don’t support NoPadding.
### Check whether an algorithm supports certain mode and padding
```swift
import Crypto

print(SymmetricCipher.Algorithm.aes.isValid(mode: .ctr, padding: .pkcs7))
// prints true
print(SymmetricCipher.Algorithm.rc4.isValid(mode: .ctr, padding: .none))
// prints false
```
### Key size and IV size
When we use Symmetric Cipher, it's important to know the valid key size and iv size.
```swift
import Crypto

// Get possible key sizes of AES algorithm
print(SymmetricCipher.Algorithm.aes.keySizes())
// prints [16, 24, 32]
// Get iv size of AES algorithm in CBC mode
print(SymmetricCipher.Algorithm.aes.ivSize(mode: .cbc))
// prints 16
// Get iv size of AES algorithm in ECB mode
print(SymmetricCipher.Algorithm.aes.ivSize(mode: .ecb))
// prints 0
// Test whether key size is valid
print(SymmetricCipher.Algorithm.aes.isValidKeySize(32))
print(SymmetricCipher.Algorithm.aes.isValidKeySize(40))
```

## Digest

### How to use
```swift
import Crypto

do {
    let plainText = "Hello world"
    let data = try plainText.data(.utf8)
    let digest = try Digest.sha256.process(data).string(.hex)
    print("Plain text: \(plainText)")
    print("SHA256: \(digest)")
} catch let error {
    print(error)
}
/*
Plain text: Hello world
SHA256: 64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c
*/
```

Or

```swift
do {
    let plainText = "I am fine"
    print(try plainText.process(.md5))
    print(try plainText.process(.sha1))
    print(try plainText.process(.sha256))
} catch let error {
    print(error)
}
```

### Iterate all algorithms

```swift
import Crypto

let plainText = "hello world"
print("Plain text: \(plainText)")
for digest in Digest.allCases {
    let digested = digest.process(plainText.data(using: .utf8)!)
    print("\(digest):\(digested.hex)")
}
/*
Plain text: hello world
md2:d9cce882ee690a5c1ce70beff3a78c77
md4:aa010fbc1d14c795d86ef98c95479d17
md5:5eb63bbbe01eeed093cb22bb8f5acdc3
sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
sha224:2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b
sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
sha384:fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd
sha512:309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
*/
```
### Supported Algorithms
* MD2
* MD4
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512

## HMAC

### How to use

```swift
import Crypto

do {
    let hmac = try HMAC(.sha256, key: "11111111111111111111".data(.hex))
    print("Result: \(try hmac.process(try "Hello world".data(.utf8)).string(.hex))")
} catch let error {
    print(error)
}
```

Or
```swift
import Crypto

let plainText = "I am fine"
let key = "11111111111111111111"
do {
    print(try plainText.process(.hmacmd5(key: key)))
    print(try plainText.process(.hmacsha256(key: key)))
} catch let error {
    print(error)
}
```
### Iterate all algorithms
```swift
import Crypto

do {
    for algorithm in HMAC.Algorithm.allCases {
        print(try "Hello world".process(.hmac(algorithm, key: "11111111111111111111")))
    }
    /*
    927021484b9e56f8b4075b3892b69e40dbfddb82
    872ff29d7346589d442d294b78ea6a45
    ddd1144470baba611751cc1ee2314aaed77dad08ee54ef207f9e45a34bde428d
    badd9044a2458d2e71f01704b313192a1a40e52a073959ec4e97dfb04892667624ac85ba687c287e7e7988457a3d7070
    767b4a6e1e3cf0e2c857b894eeae3d0d4584ac3e6312fb8934315fa6c83c6a614244a2a3605cc9e978933d052115c260e1f75a66cde07ba7a8a11b034b1f500c
    72a89b5586710450fb0739c96aebb4de780c2c820fe238892ee4e7e2
    */
} catch let error {
    print(error)
}
```
### Supported Algorithms
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512
