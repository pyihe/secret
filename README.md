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
package main

import (
	"crypto/rand"
	"fmt"
	"github.com/pyihe/secret"
	"io"
)

func main() {
    var c = secret.NewCipher()
    var nonce = make([]byte, 12) // 随机向量
    _, _ = io.ReadFull(rand.Reader, nonce)
    //encrypt
    var encryptReq = &secret.SymRequest{
        PlainData:   "I Love China!",
        Key:         []byte("1234567812345678"),
        Type:        secret.SymTypeAES,
        ModeType:    secret.BlockModeGCM,
        PaddingType: secret.PaddingTypeNoPadding,
        AddData:     []byte("this is additional data"),
        Nonce:       nonce,
    }
    cipherStr, err := c.SymEncryptToString(encryptReq)
    if err != nil {
        //handle err
    }
    
    //decrypt
    //if decrypts in another server with GCM mode, then your need to set nonce to decrypt
    var decryptReq = &secret.SymRequest{
        PlainData:   nil,
        CipherData:  cipherStr,
        Key:         []byte("1234567812345678"),
        Type:        secret.SymTypeAES,
        ModeType:    secret.BlockModeGCM,
        PaddingType: secret.PaddingTypeNoPadding,
        AddData:     []byte("this is additional data"),
        Nonce:       nonce, // this value must be the same with encryptReq
    }
    plainBytes, err := c.SymDecrypt(decryptReq)
    if err != nil {
        //handle err
    }
    //unmarshal plainBytes or use it directly
    
    //c.SetRSAKey(privateKey, secret.PKCSLevel1) to set key if key is already exist
    _, _, err = c.GenerateRSAKey(4096, "../conf", secret.PKCSLevel1)
    if err != nil {
        //handle err
    }
    
    cipherStr, err = c.RSAEncryptToString(plainBytes, secret.RSAEncryptTypeOAEP, nil)
    if err != nil {
        //handle err
    }
    plainBytes, err = c.RSADecrypt(cipherStr, secret.RSAEncryptTypeOAEP, nil)
    if err != nil {
        //handle err
    }
    //output: I Love China!
    fmt.Printf("%s\n", plainBytes)
}
```