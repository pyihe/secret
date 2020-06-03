package secret

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path"
	"secret/pkg"
	"sync"
)

const (
	PKCSLevel1 pKCSLevel = iota + 1 //PKCS#1
	PKCSLevel8                      //PKCS#8
)

const (
	RSAEncryptTypeOAEP     rSAEncryptType = iota + 1 //使用RSA-OAEP算法加密, 推荐使用
	RSAEncryptTypePKCS1v15                           //使用PKCS#1 v1.5规定的填充方案和RSA算法加密，加密的数据量有限
)

const (
	RSASignTypePKCS1v15 rSASignTyp = iota + 1
	RSASignTypePSS
)

var (
	defaultAsyCipher = &asyCipher{}
	once             sync.Once
)

type (
	pKCSLevel      uint //PKCS标准类型, 用于生成密钥文件
	rSAEncryptType uint //RSA加密算法类型, 用于加密、解密
	rSASignTyp     uint //RSA签名类型

	asyCipher struct {
		rsaPrivateKey *rsa.PrivateKey   //RSA私钥
		eccPrivateKey *ecdsa.PrivateKey //ECC私钥
	}
)

//初始化RSA解码器，PKCSLevel填私钥的生成规范标准(PKCS#1, PKCS#8, 默认PKCS#1)
//参数均为必填参数，密钥不论是既有还是调用GenerateRSAKey生成，都需要将密钥路径传入本函数
//pkcsLevel对应生成密钥时选择的PKCSLevel，默认PKCS#1
func NewAsyCipher() AsyCipher {
	return defaultAsyCipher
}

//如果是既有的密钥对，需要调用此方法设置RSA私钥(pkcsLevel 为生成密钥时的规范，默认为PKCSLevel1)
func (m *asyCipher) SetRSAKey(privateFile string, pkcsLevel pKCSLevel) error {
	privateKey, err := getPrivateKey(privateFile, pkcsLevel)
	if err != nil {
		return err
	}
	m.rsaPrivateKey = privateKey
	return nil
}

/*	生成RSA密钥对
	参数解析:
	bits: 密钥的长度
	saveDir: 密钥文件的保存目录
	pkcsLevel: 生成密钥的规范: PKCS1(PKCS#1) 和PKCS8(PKCS#8)
*/
func (m *asyCipher) GenerateRSAKey(bits int, saveDir string, pkcsLevel pKCSLevel) (privateFile, publicFile string, err error) {
	/*
		1. 生成RSA密钥对
		2. 将私钥对象转换为DER编码形式
		3. 创建私钥(公钥)文件
		4. 对密钥信息进行pem编码并写入私钥文件中
	*/
	privateData, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}

	var privateBytes, publicBytes []byte
	switch pkcsLevel {
	case PKCSLevel1:
		privateBytes = x509.MarshalPKCS1PrivateKey(privateData)
		publicBytes = x509.MarshalPKCS1PublicKey(&privateData.PublicKey)
	case PKCSLevel8:
		privateBytes, err = x509.MarshalPKCS8PrivateKey(privateData)
		if err != nil {
			return
		}
		publicBytes, err = x509.MarshalPKIXPublicKey(&privateData.PublicKey)
		if err != nil {
			return
		}
	default:
		err = pkg.ErrInvalidPKCSLevel
		return
	}

	privatePath := path.Join(saveDir, "private.pem")
	file, err := os.Create(privatePath)
	if err != nil {
		return
	}
	defer file.Close()

	var block = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateBytes,
	}
	if err = pem.Encode(file, block); err != nil {
		return
	}

	//创建公钥
	publicPath := path.Join(saveDir, "public.pem")
	file, err = os.Create(publicPath)
	if err != nil {
		return
	}

	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}
	if err = pem.Encode(file, block); err != nil {
		return
	}

	m.rsaPrivateKey = privateData

	return privatePath, publicPath, nil
}

/*
	使用公钥加密
	参数解析:
	originalData: 需要加密的原始数据
	rsaPublicKey: 公钥路径
	rsaType: ras加密类型, OAEP和PKCS1v15(推荐使用OAEP)
	label: 当rsaType为OAEP时传值, 不需要时传nil(加密和解密时的label必须一致)
*/
func (m *asyCipher) RSAEncryptToBytes(originalData interface{}, rsaType rSAEncryptType, label []byte) (encryptData []byte, err error) {
	if m.rsaPrivateKey == nil {
		err = pkg.ErrNoPrivateKey
		return
	}
	bytes, err := getBytes(originalData)
	if err != nil {
		return
	}
	switch rsaType {
	case RSAEncryptTypeOAEP:
		encryptData, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &m.rsaPrivateKey.PublicKey, bytes, label)
	case RSAEncryptTypePKCS1v15:
		encryptData, err = rsa.EncryptPKCS1v15(rand.Reader, &m.rsaPrivateKey.PublicKey, bytes)
	}
	return
}

/*
	RSA加密字符串
*/
func (m *asyCipher) RSAEncryptToString(originalData interface{}, rsaType rSAEncryptType, label []byte) (encryptData string, err error) {
	encryptBytes, err := m.RSAEncryptToBytes(originalData, rsaType, label)
	if err != nil {
		return
	}
	encryptData = base64.StdEncoding.EncodeToString(encryptBytes)
	return
}

//私钥解密
/*
	使用私钥解密
	参数解析:
	encryptData: 密文
	rsaPrivateKey: 密钥文件路径
	pkcsLevel: 密钥生成时选择的标准类型(PKCSLevel1和PKCSLevel8)
	rsaType: 解密类型, 与加密类型对应（OAEP和PKCS1v15）
	label: 当rsaType为OAEP时传值，不需要时传nil
*/
func (m *asyCipher) RSADecryptBytes(encryptData []byte, rsaType rSAEncryptType, label []byte) (originalData []byte, err error) {
	if m.rsaPrivateKey == nil {
		err = pkg.ErrNoPrivateKey
		return
	}
	switch rsaType {
	case RSAEncryptTypeOAEP:
		originalData, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, m.rsaPrivateKey, encryptData, label)

	case RSAEncryptTypePKCS1v15:
		originalData, err = rsa.DecryptPKCS1v15(rand.Reader, m.rsaPrivateKey, encryptData)

	default:
		err = pkg.ErrInvalidRSAType
		return
	}
	return
}

/*
	RSA解密字符串
*/
func (m *asyCipher) RSADecryptString(encryptData string, rsaType rSAEncryptType, label []byte) (originalData []byte, err error) {
	encryptBytes, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return
	}
	return m.RSADecryptBytes(encryptBytes, rsaType, label)
}

/*
	用私钥进行数字签名
	参数解析:
	data: 需要签名的原始数据
	rsaPrivateKey: 私钥文件路径
	pkcsLevel: 生成密钥时使用的规范类型(PKCSLevel1和PKCSLevel8)
	signType: 签名算法类型(SignTypePKCS1v15和SignTypePSS)
	hashType: hash计算类型
*/
func (m *asyCipher) RSASignToBytes(data interface{}, signType rSASignTyp, hashType crypto.Hash) (signedData []byte, err error) {
	/*	签名流程:
		1. 获取用于签名的私钥
		2. 计算原始数据的hash值
		3. 用私钥加密(签名)
	*/
	if m.rsaPrivateKey == nil {
		err = pkg.ErrNoPrivateKey
		return
	}

	hasher := NewHasher()
	hashed, err := hasher.HashToBytes(data, hashType)
	if err != nil {
		return nil, err
	}

	switch signType {
	case RSASignTypePKCS1v15:
		signedData, err = rsa.SignPKCS1v15(rand.Reader, m.rsaPrivateKey, hashType, hashed)
	case RSASignTypePSS:
		signedData, err = rsa.SignPSS(rand.Reader, m.rsaPrivateKey, hashType, hashed, nil)
	default:
		err = pkg.ErrInvalidSignType
	}
	return signedData, err
}

//签名字符串
func (m *asyCipher) RSASignToString(data interface{}, signType rSASignTyp, hashType crypto.Hash) (string, error) {
	signBytes, err := m.RSASignToBytes(data, signType, hashType)
	if err != nil {
		return "", err
	}
	result := base64.StdEncoding.EncodeToString(signBytes)
	return result, nil
}

/*
	用公钥验证数字签名
	参数解析:
	signedData: 私钥签了名的数据
	originalData: 原始数据
	rsaPublicKey: 公钥文件路径
	signType: 签名算法类型, 与签名时的对应一致
	hashType: hash类型, 与签名时的对应一致
*/
func (m *asyCipher) RSAVerifySignBytes(signedData []byte, originalData interface{}, signType rSASignTyp, hashType crypto.Hash) (ok bool, err error) {
	/*	验证签名流程:
		1. 获取公钥信息
		2. 计算原始数据的hash值
		2. 验签
	*/
	//获取公钥数据
	if m.rsaPrivateKey == nil {
		err = pkg.ErrNoPrivateKey
		return
	}
	//计算原始数据的hash值
	hasher := NewHasher()
	hashed, err := hasher.HashToBytes(originalData, hashType)
	if err != nil {
		return false, err
	}

	//验证签名
	switch signType {
	case RSASignTypePKCS1v15:
		err = rsa.VerifyPKCS1v15(&m.rsaPrivateKey.PublicKey, hashType, hashed, signedData)
	case RSASignTypePSS:
		err = rsa.VerifyPSS(&m.rsaPrivateKey.PublicKey, hashType, hashed, signedData, nil)
	default:
		err = pkg.ErrInvalidSignType
	}

	return err == nil, err
}

//验证字符串签名
func (m *asyCipher) RSAVerifySignString(signedData string, originalData interface{}, signType rSASignTyp, hashType crypto.Hash) (ok bool, err error) {
	signBytes, err := base64.StdEncoding.DecodeString(signedData)
	if err != nil {
		return false, err
	}
	return m.RSAVerifySignBytes(signBytes, originalData, signType, hashType)
}

func getPrivateKey(privateFile string, pkcsLevel pKCSLevel) (keyData *rsa.PrivateKey, err error) {
	keyBytes, err := ioutil.ReadFile(privateFile)
	if err != nil {
		return
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		err = pkg.ErrPemReadFail
		return
	}
	switch pkcsLevel {
	case PKCSLevel8:
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		keyData, _ = keyInterface.(*rsa.PrivateKey);
		if keyData == nil {
			err = pkg.ErrPemReadFail
			return nil, err
		}

	default:
		keyData, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return
		}
	}
	return
}

func getPublicKey(publicFile string, pkcsLevel pKCSLevel) (keyData *rsa.PublicKey, err error) {
	keyBytes, err := ioutil.ReadFile(publicFile)
	if err != nil {
		return
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, pkg.ErrPemReadFail
	}

	switch pkcsLevel {
	case PKCSLevel8:
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		keyData, _ = pub.(*rsa.PublicKey)
		if keyData == nil {
			err = pkg.ErrPemReadFail
			return nil, err
		}
	default:
		keyData, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}
	return
}

//TODO rsa.DecryptPKCS1v15SessionKey()
