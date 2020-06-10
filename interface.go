package secret

import (
	"crypto"
	"crypto/dsa"
)

/*
	这里封装有：
	Cipher: RC4, DES, 3DES, AES, RSA
	数字签名: RSA, ECC, DSA
	Hash函数、消息验证码
*/

//对称加密器（包括DES/3DES/AES/RC4）
type Cipher interface {
	//RC4
	//加密，返回[]byte
	RC4EncryptToBytes(data interface{}, key []byte) ([]byte, error)
	//解密[]byte
	RC4DecryptBytes(encryptData []byte, key []byte) ([]byte, error)
	//加密，返回base64 string
	RC4EncryptToString(data interface{}, key []byte) (string, error)
	//解密base64 string
	RC4DecryptString(encryptData string, key []byte) ([]byte, error)

	//AES/DES/3DES
	//加密，返回[]byte
	SymEncryptToBytes(data interface{}, key []byte, encryptType symType, modeType blockMode, paddingType paddingType) (encryptData []byte, err error)
	//加密，返回base64 string
	SymEncryptToString(data interface{}, key []byte, encryptType symType, modeType blockMode, paddingType paddingType) (encryptString string, err error)
	//解密[]byte
	SymDecryptBytes(encryptData, key []byte, t symType, modeType blockMode, paddingType paddingType) (originalData []byte, err error)
	//解密base64 string
	SymDecryptString(encryptData string, key []byte, t symType, modeType blockMode, paddingType paddingType) (originalData []byte, err error)

	//RSA
	//设置密钥
	SetRSAKey(privateFile string, pkcsLevel pKCSLevel) error
	//生成密钥对
	GenerateRSAKey(bits int, saveDir string, pkcsLevel pKCSLevel) (privateFile, publicFile string, err error)
	//加密,返回[]byte
	RSAEncryptToBytes(data interface{}, rsaType rSAEncryptType, label []byte) (cipherBytes []byte, err error)
	//加密，返回base64 string
	RSAEncryptToString(data interface{}, rsaType rSAEncryptType, label []byte) (cipherString string, err error)
	//解密[]byte
	RSADecryptBytes(cipherBytes []byte, rsaType rSAEncryptType, label []byte) (data []byte, err error)
	//解密base64 string
	RSADecryptString(cipherString string, rsaType rSAEncryptType, label []byte) (data []byte, err error)
	//签名, 返回[]byte
	RSASignToBytes(data interface{}, signType rSASignTyp, hashType crypto.Hash) (signBytes []byte, err error)
	//签名, 返回string
	RSASignToString(data interface{}, signType rSASignTyp, hashType crypto.Hash) (signString string, err error)
	//验证[]byte签名结果
	RSAVerifySignBytes(signBytes []byte, data interface{}, signType rSASignTyp, hashType crypto.Hash) (ok bool, err error)
	//验证base64 string签名结果
	RSAVerifySignString(signString string, data interface{}, signType rSASignTyp, hashType crypto.Hash) (ok bool, err error)
}

//hash
type Hasher interface {
	HashToString(data interface{}, hashType crypto.Hash) (hashString string, err error)
	HashToBytes(data interface{}, hashType crypto.Hash) (hashBytes []byte, err error)
	DoubleHashToString(data interface{}, hashType crypto.Hash) (hashString string, err error)
	DoubleHashToBytes(data interface{}, hashType crypto.Hash) (hashBytes []byte, err error)
	MAC(hashType crypto.Hash, message, key []byte) (mac []byte)
	CheckMac(hashType crypto.Hash, message, key, mac []byte) bool
}

//数字签名
type Signer interface {
	//ECC椭圆曲线签名
	SetECCKey(privateFile string) error
	GenerateEccKey(curveType eccCurveType, saveDir string) (privateFile, publicFile string, err error)
	EccSignToBytes(data interface{}, hashType crypto.Hash) ([]byte, error)
	EccSignToString(data interface{}, hashType crypto.Hash) (string, error)
	EccVerifySignBytes(signData []byte, originalData interface{}, hashType crypto.Hash) (ok bool, err error)
	EccVerifySignString(signData string, originalData interface{}, hashType crypto.Hash) (bool, error)

	//DSA签名
	SetDSAKey(size dsa.ParameterSizes) (err error)
	DSASignToBytes(data interface{}, hashType crypto.Hash) ([]byte, error)
	DSASignToString(data interface{}, hashType crypto.Hash) (string, error)
	DSAVerifyBytes(data interface{}, signed []byte, hashType crypto.Hash) (bool, error)
	DSAVerifyString(data interface{}, signed string, hashType crypto.Hash) (bool, error)
}
