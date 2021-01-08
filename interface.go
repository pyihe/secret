package secret

import (
	"crypto"
	"crypto/dsa"
	"crypto/ed25519"
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
	//加密，返回base64 string
	RC4EncryptToString(data interface{}, key []byte) (string, error)
	//解密[]byte
	RC4Decrypt(encryptData interface{}, key []byte) ([]byte, error)

	//AES/DES/3DES
	GetGCMNonce() []byte      //GCM模式下获取nonce，需要传递给解密方
	SetGCMNonce(nonce []byte) //如果使用GCM模式解密，需要通过此方法设置nonce，再执行解密
	//加密，返回[]byte
	SymEncryptToBytes(request *SymRequest) (encryptData []byte, err error)
	//加密，返回base64 string
	SymEncryptToString(request *SymRequest) (encryptString string, err error)
	//解密[]byte
	SymDecrypt(request *SymRequest) (originalData []byte, err error)

	//RSA
	//设置私钥
	SetRSAPrivateKey(privateFile interface{}, pkcsLevel pKCSLevel) error
	//设置公钥
	SetRSAPublicKey(publicData interface{}, level pKCSLevel) error
	//生成密钥对
	GenerateRSAKey(bits int, saveDir string, pkcsLevel pKCSLevel) (privateFile, publicFile string, err error)
	//加密,返回[]byte
	RSAEncryptToBytes(data interface{}, rsaType rSAEncryptType, label []byte) (cipherBytes []byte, err error)
	//加密，返回base64 string
	RSAEncryptToString(data interface{}, rsaType rSAEncryptType, label []byte) (cipherString string, err error)
	//解密
	RSADecrypt(cipherBytes interface{}, rsaType rSAEncryptType, label []byte) (data []byte, err error)
	//签名, 返回[]byte
	RSASignToBytes(data interface{}, signType rSASignType, hashType crypto.Hash) (signBytes []byte, err error)
	//签名, 返回string
	RSASignToString(data interface{}, signType rSASignType, hashType crypto.Hash) (signString string, err error)
	//验证签名结果
	RSAVerify(signBytes interface{}, data interface{}, signType rSASignType, hashType crypto.Hash) (ok bool, err error)
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
	GenerateECCKey(curveType eccCurveType, saveDir string) (privateFile, publicFile string, err error)
	EccSignToBytes(data interface{}, hashType crypto.Hash) ([]byte, error)
	EccSignToString(data interface{}, hashType crypto.Hash) (string, error)
	EccVerify(signData interface{}, originalData interface{}, hashType crypto.Hash) (ok bool, err error)

	//DSA签名
	GenerateDSAKey(size dsa.ParameterSizes) (err error)
	GetDSAPrivateKey() *dsa.PrivateKey
	DSASignToBytes(data interface{}, hashType crypto.Hash) ([]byte, error)
	DSASignToString(data interface{}, hashType crypto.Hash) (string, error)
	DSAVerify(data interface{}, signed interface{}, hashType crypto.Hash) (bool, error)

	//Ed25519签名
	GetEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey)
	Ed25519SignToBytes(data interface{}) ([]byte, error)
	Ed25519SignToString(data interface{}) (string, error)
	Ed25519Verify(data interface{}, signed interface{}) (bool, error)
}
