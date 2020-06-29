# [secret](https://github.com/pyihe/secret)
usual encryption algorithm written in go

#### Function
##### Cipher
|Type|Mode|Padding|
|:----|:----|:----|
|DES|ECB/CBC|PKCS5/PKCS7/Zero/None|
|3DES|ECB/CBC|PKCS5/PKCS7/Zero/None|
|AES|ECB/CBC|PKCS5/PKCS7/Zero/None|
|DES|CFB/OFB/CTR/GCM||
|3DES|CFB/OFB/CTR/GCM||
|AES|CFB/OFB/CTR/GCM||
|RC4 |-|-|
|RSA|Encrypt/Decrypt/Sign/Verify|-|

##### Hash  
|Name|
|:---|
|Hash|
|DoubleHash|

##### Sign&&Verify
|Name|Description|
|:---|:----------|
|ECC(ECDSA) |Sign/Verify|
|DSA|Sign/Verify|
|EdDSA|Sign/Verify|


#### Example
```go
//RSA encrypt, decrypt
var data  = "usual encryption algorithm written in go"
var label = []byte("label")
c := secret.NewCipher()
//if GenerateRSAKey is not called, then you must call SetRSAKey to set yourself private key.
//SetRSAKey is not necessary if GenerateRSAKey is called.
//c.SetRSAKey("your privateKey file", secret.PKCSLevel1)
_, _, err := c.GenerateRSAKey(1024, "conf", secret.PKCSLevel1)
if err != nil {
    log.Fatalf("exit with generate key err: %v\n", err)
}
encryptData, err := c.RSAEncryptToString(data, secret.RSAEncryptTypeOAEP, label)
if err != nil {
    log.Fatalf("exit with encrypt err: %v\n", err)
}
log.Printf("after encrypt, encrypt data = %s\n", encryptData)
originalData, err := c.RSADecrypt(encryptData, secret.RSAEncryptTypeOAEP, label)
if err != nil {
    log.Fatalf("exit with decrypt err: %v\n", err)
}
log.Printf("after decrypt, data = %s\n", originalData)
```
run result:

![](pic/rsa.jpg)


```go
//AES encrypt, decrypt
s := secret.NewCipher()
var cipherReq = &SymRequest{
    PlainData:   "usual encryption algorithm written in go",
    CipherData:  nil,
    Key:         []byte("1234567812345678"),
    Type:        SymTypeAES,
    ModeType:    BlockModeGCM,
    PaddingType: PaddingTypeNoPadding,
    AddData:     nil,
}
cipherText, err := s.SymEncryptToString(cipherReq)
if err != nil {
    log.Fatalf("exit in SymEncryptString with err: %v\n", err)
}
log.Printf("cipher text = %s\n", cipherText)
var decryptReq = &SymRequest{
    PlainData:   nil,
    CipherData:  cipherText,
    Key:         []byte("1234567812345678"),
    Type:        SymTypeAES,
    ModeType:    BlockModeGCM,
    PaddingType: PaddingTypeNoPadding,
    AddData:     nil,
}
plainText, err := s.SymDecrypt(decryptReq)
if err != nil {
    log.Fatalf("exit in SymDecryptString with err: %v\n", err)
}
log.Printf("plain text = %s\n", plainText)

//hash
h := secret.NewHasher()
hashString, err := h.HashToString(data, crypto.SHA256)
if err != nil {
    log.Fatalf("exit with HashToString err: %v\n", err)
}
log.Printf("hash result = %v\n", hashString)
```
run result: 

![](pic/sym.jpg)