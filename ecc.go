package secret

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"secret/pkg"
)

const (
	ECCCurveTypeP224 eccCurveType = iota + 1
	ECCCurveTypeP256
	ECCCurveTypeP384
	ECCCurveTypeP521
)

type eccCurveType uint

//如果是既有的密钥对，需要调用此方法设置ECC私钥
func (m *asyCipher) SetECCKey(privateFile string) error {
	privateKey, err := getEccPrivateKey(privateFile)
	if err != nil {
		return err
	}
	m.eccPrivateKey = privateKey
	return nil
}

//生成椭圆曲线密钥对
func (m *asyCipher) GenerateEccKey(curveType eccCurveType, saveDir string) (privateFile, publicFile string, err error) {
	c, err := getCurveInstance(curveType)
	if err != nil {
		return
	}
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return
	}
	privateBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateBytes,
	}

	privateFile = path.Join(saveDir, "ecPrivate.pem")
	file, err := os.Create(privateFile)
	if err != nil {
		return
	}
	defer file.Close()

	if err = pem.Encode(file, block); err != nil {
		return
	}

	//生成公钥
	publicKey := &privateKey.PublicKey
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}
	block.Type = "PUBLIC KEY"
	block.Bytes = publicBytes
	publicFile = path.Join(saveDir, "ecPublic.pem")
	file, err = os.Create(publicFile)
	if err != nil {
		return
	}
	if err = pem.Encode(file, block); err != nil {
		return
	}
	m.eccPrivateKey = privateKey
	return
}

//ECC数字签名
func (m *asyCipher) EccSignToBytes(data interface{}, hashType crypto.Hash) ([]byte, error) {
	if m.eccPrivateKey == nil {
		return nil, pkg.ErrNoPrivateKey
	}
	hasher := NewHasher()
	hash, err := hasher.HashToBytes(data, hashType)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, m.eccPrivateKey, hash)
	if err != nil {
		return nil, err
	}
	rBytes, err := r.MarshalText()
	if err != nil {
		return nil, err
	}
	sBytes, err := s.MarshalText()
	if err != nil {
		return nil, err
	}
	//通过|将两个切片合并，并返回
	result := append(rBytes, byte('|'))
	result = append(result, sBytes...)
	return result, nil
}

//ECC签名字符串
func (m *asyCipher) EccSignToString(data interface{}, hashType crypto.Hash) (string, error) {
	bytes, err := m.EccSignToBytes(data, hashType)
	if err != nil {
		return "", err
	}
	result := base64.StdEncoding.EncodeToString(bytes)
	return result, nil
}

//ECC数字签名验证
func (m *asyCipher) EccVerifySignBytes(signData []byte, originalData interface{}, hashType crypto.Hash) (ok bool, err error) {
	if m.eccPrivateKey == nil {
		err = pkg.ErrNoPrivateKey
		return
	}
	hasher := NewHasher()
	hash, err := hasher.HashToBytes(originalData, hashType)
	if err != nil {
		return
	}
	bytesArray := bytes.Split(signData, []byte("|"))
	var r, s big.Int
	if err := r.UnmarshalText(bytesArray[0]); err != nil {
		return false, err
	}
	if err := s.UnmarshalText(bytesArray[1]); err != nil {
		return false, err
	}
	ok = ecdsa.Verify(&m.eccPrivateKey.PublicKey, hash, &r, &s)
	return
}

//ECC验证字符串签名
func (m *asyCipher) EccVerifySignString(signData string, originalData interface{}, hashType crypto.Hash) (bool, error) {
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return false, err
	}
	return m.EccVerifySignBytes(sign, originalData, hashType)
}

func getEccPrivateKey(privateFile string) (privateKey *ecdsa.PrivateKey, err error) {
	keyBytes, err := ioutil.ReadFile(privateFile)
	if err != nil {
		return
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		err = pkg.ErrPemReadFail
		return
	}
	privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	return
}

func getEccPublicKey(publicFile string) (publicKey *ecdsa.PublicKey, err error) {
	keyBytes, err := ioutil.ReadFile(publicFile)
	if err != nil {
		return
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, pkg.ErrPemReadFail
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, _ = pub.(*ecdsa.PublicKey)
	if publicKey == nil {
		err = pkg.ErrPemReadFail
	}
	return
}

func getCurveInstance(t eccCurveType) (elliptic.Curve, error) {
	var c elliptic.Curve
	var err error
	switch t {
	case ECCCurveTypeP224:
		c = elliptic.P224()
	case ECCCurveTypeP256:
		c = elliptic.P256()
	case ECCCurveTypeP384:
		c = elliptic.P384()
	case ECCCurveTypeP521:
		c = elliptic.P521()
	default:
		err = pkg.ErrInvalidEccType
	}
	return c, err
}
