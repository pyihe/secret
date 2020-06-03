# [secret](https://github.com/pyihe/secret)
usual encryption algorithm written in go

#### Function
##### Symmetrical Encryption
|Name|Support Data Type|Description|Padding|
|:---|:----------------|:----------|:------|
|DES |interface        |CBC/ECB/CFB/OFB |PKCS#5/PKCS#7/Zero/None|
|3DES|interface        |CBC/ECB/CFB/OFB|PKCS#5/PKCS#7/Zero/None|
|AES |interface        |CBC/ECB/CFB/OFB|PKCS#5/PKCS#7/Zero/None|
|RC4 |interface        |-|-|

##### Hash  
|Name|Support Data Type|
|:---|:----------|
|Hash|interface|
|DoubleHash|interface|

##### Asymmetric Encryption
|Name|Support Data Type|Description|
|:---|:----------------|:----------|
|RSA |interface        |Encrypt/Decrypt/Sign/VerifySign|
|ECC |interface        |Sign/VerifySign|


#### Example
```go
//RSA encrypt, decrypt
var data  = "usual encryption algorithm written in go"
var label = []byte("label")
c := secret.NewAsyCipher()
//if GenerateRSAKey is not called, then you must call SetRSAKey to set yourself private key.
//SetRSAKey is not necessary if GenerateRSAKey is called(this situation is same for ECC).
//c.SetRSAKey("your privateKey file", secret.PKCSLevel1)
_, _, err := c.GenerateRSAKey(1024, "conf", secret.PKCSLevel1)
if err != nil {
    log.Fatalf("exit with generate key err: %v\n", err)
}
encryptData, err := c.RSAEncryptString(data, secret.RSAEncryptTypeOAEP, label)
if err != nil {
    log.Fatalf("exit with encrypt err: %v\n", err)
}
log.Printf("after encrypt, encrypt data = %s\n", encryptData)
originalData, err := c.RSADecryptString(encryptData, secret.RSAEncryptTypeOAEP, label)
if err != nil {
    log.Fatalf("exit with decrypt err: %v\n", err)
}
log.Printf("after decrypt, data = %s\n", originalData)
```
run result:

![](pic/rsa.jpg)


```go
//AES encrypt, decrypt
data = "usual encryption algorithm written in go"
key  = "1234567812345678"
s := secret.NewSymCipher()
cipherText, err := s.SymEncryptString(data, key, secret.SymTypeAES, secret.BlockModeECB, secret.PaddingTypeZeros)
if err != nil {
    log.Fatalf("exit in SymEncryptString with err: %v\n", err)
}
log.Printf("cipher text = %s\n", cipherText)
plainText, err := s.SymDecryptString(cipherText, key, secret.SymTypeAES, secret.BlockModeECB, secret.PaddingTypeZeros)
if err != nil {
    log.Fatalf("exit in SymDecryptString with err: %v\n", err)
}
log.Printf("plain text = %s\n", plainText)

//hash
hash, err := s.HashString(data, crypto.SHA256, false)
if err != nil {
    log.Fatalf("exit in HashString with err: %v\n", err)
}
log.Printf("hash result = %s\n", hash)
```
run result: 

![](pic/sym.jpg)