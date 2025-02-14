package secret

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path"

	"github.com/pyihe/secret/pkg"
)

const (
	ECCCurveTypeP224 EccCurveType = iota + 1
	ECCCurveTypeP256
	ECCCurveTypeP384
	ECCCurveTypeP521
)

type EccCurveType uint

type mySigner struct {
	eccPrivateKey     *ecdsa.PrivateKey  //ECC私钥
	dsaPrivateKey     *dsa.PrivateKey    //DSA私钥
	ed25519PrivateKey ed25519.PrivateKey //Ed25519私钥
	ed25519PublicKey  ed25519.PublicKey  //Ed25519公钥
}

func NewSigner() Signer {
	return &mySigner{}
}

// 如果是既有的密钥对，需要调用此方法设置ECC私钥
func (m *mySigner) SetECCKey(privateFile string) error {
	privateKey, err := getEccPrivateKey(privateFile)
	if err != nil {
		return err
	}
	m.eccPrivateKey = privateKey
	return nil
}

func (m *mySigner) GetDSAPrivateKey() *dsa.PrivateKey {
	return m.dsaPrivateKey
}

func (m *mySigner) GetEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(m.ed25519PublicKey) == 0 || len(m.ed25519PrivateKey) == 0 {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil
		}
		m.ed25519PrivateKey = privateKey
		m.ed25519PublicKey = publicKey
	}
	return m.ed25519PublicKey, m.ed25519PrivateKey
}

/*
	ECC签名相关
*/
//生成椭圆曲线密钥对
func (m *mySigner) GenerateECCKey(curveType EccCurveType, saveDir string) (privateFile, publicFile string, err error) {
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

	if err = pem.Encode(file, block); err != nil {
		return
	}
	file.Close()
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
	file.Close()
	m.eccPrivateKey = privateKey
	return
}

// ECC数字签名
func (m *mySigner) EccSignToBytes(data interface{}, hashType crypto.Hash) ([]byte, error) {
	if m.eccPrivateKey == nil {
		return nil, pkg.ErrNoPrivateKey
	}
	hash, err := defaultHasher.HashToBytes(data, hashType)
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

// ECC签名字符串
func (m *mySigner) EccSignToString(data interface{}, hashType crypto.Hash) (string, error) {
	bytes, err := m.EccSignToBytes(data, hashType)
	if err != nil {
		return "", err
	}
	result := base64.StdEncoding.EncodeToString(bytes)
	return result, nil
}

// ECC数字签名验证
func (m *mySigner) EccVerify(signed interface{}, originalData interface{}, hashType crypto.Hash) (ok bool, err error) {
	if m.eccPrivateKey == nil {
		err = pkg.ErrNoPrivateKey
		return
	}
	hash, err := defaultHasher.HashToBytes(originalData, hashType)
	if err != nil {
		return
	}
	var sig []byte
	switch t := signed.(type) {
	case string:
		if len(t) == 0 {
			return false, pkg.ErrNoCipher
		}
		sig, err = base64.StdEncoding.DecodeString(t)
		if err != nil {
			return false, err
		}
	case []byte:
		if len(t) == 0 {
			return false, pkg.ErrNoCipher
		}
		sig = t
	default:
		return false, pkg.ErrInvalidCipherText
	}
	bytesArray := bytes.Split(sig, []byte("|"))
	if len(bytesArray) != 2 {
		err = pkg.ErrDataInvalidBytes
		return
	}
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

/*
DSA签名相关
*/
func (m *mySigner) GenerateDSAKey(size dsa.ParameterSizes) (err error) {
	var param dsa.Parameters
	if err = dsa.GenerateParameters(&param, rand.Reader, size); err != nil {
		return
	}
	var privateKey = &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: param,
		},
	}
	if err = dsa.GenerateKey(privateKey, rand.Reader); err != nil {
		return
	}
	m.dsaPrivateKey = privateKey
	return nil
}

func (m *mySigner) DSASignToBytes(data interface{}, hashType crypto.Hash) ([]byte, error) {
	if m.dsaPrivateKey == nil {
		return nil, pkg.ErrNoPrivateKey
	}
	hash, err := defaultHasher.HashToBytes(data, hashType)
	if err != nil {
		return nil, err
	}

	r, s, err := dsa.Sign(rand.Reader, m.dsaPrivateKey, hash)
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
	result := append(rBytes, byte('|'))
	result = append(result, sBytes...)
	return result, nil
}

func (m *mySigner) DSASignToString(data interface{}, hashType crypto.Hash) (string, error) {
	bytes, err := m.DSASignToBytes(data, hashType)
	if err != nil {
		return "", err
	}
	result := base64.StdEncoding.EncodeToString(bytes)
	return result, nil
}

func (m *mySigner) DSAVerify(data interface{}, signed interface{}, hashType crypto.Hash) (bool, error) {
	if m.dsaPrivateKey == nil {
		return false, pkg.ErrNoPrivateKey
	}
	hash, err := defaultHasher.HashToBytes(data, hashType)
	if err != nil {
		return false, err
	}
	var sig []byte
	switch t := signed.(type) {
	case string:
		if len(t) == 0 {
			return false, pkg.ErrNoCipher
		}
		sig, err = base64.StdEncoding.DecodeString(t)
		if err != nil {
			return false, err
		}
	case []byte:
		if len(t) == 0 {
			return false, pkg.ErrNoCipher
		}
		sig = t
	default:
		return false, pkg.ErrInvalidCipherText
	}
	intBytes := bytes.Split(sig, []byte("|"))
	if len(intBytes) != 2 {
		return false, pkg.ErrDataInvalidBytes
	}
	var r, s big.Int
	if err = r.UnmarshalText(intBytes[0]); err != nil {
		return false, err
	}
	if err = s.UnmarshalText(intBytes[1]); err != nil {
		return false, err
	}
	ok := dsa.Verify(&m.dsaPrivateKey.PublicKey, hash, &r, &s)
	return ok, nil
}

func (m *mySigner) Ed25519SignToBytes(data interface{}) ([]byte, error) {
	if len(m.ed25519PublicKey) == 0 || len(m.ed25519PrivateKey) == 0 {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		m.ed25519PrivateKey = privateKey
		m.ed25519PublicKey = publicKey
	}
	bytes, err := getBytes(data)
	if err != nil {
		return nil, err
	}
	result := ed25519.Sign(m.ed25519PrivateKey, bytes)
	return result, nil
}

func (m *mySigner) Ed25519SignToString(data interface{}) (string, error) {
	bytes, err := m.Ed25519SignToBytes(data)
	if err != nil {
		return "", err
	}
	result := base64.StdEncoding.EncodeToString(bytes)
	return result, nil
}

func (m *mySigner) Ed25519Verify(data interface{}, signed interface{}) (bool, error) {
	if len(m.ed25519PublicKey) == 0 {
		return false, pkg.ErrNoPrivateKey
	}
	bytes, err := getBytes(data)
	if err != nil {
		return false, err
	}
	var sig []byte
	switch t := signed.(type) {
	case string:
		if len(t) == 0 {
			return false, pkg.ErrNoCipher
		}
		sig, err = base64.StdEncoding.DecodeString(t)
		if err != nil {
			return false, err
		}
	case []byte:
		if len(t) == 0 {
			return false, pkg.ErrNoCipher
		}
		sig = t
	default:
		return false, pkg.ErrInvalidCipherText
	}
	ok := ed25519.Verify(m.ed25519PublicKey, bytes, sig)
	return ok, nil
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

func getCurveInstance(t EccCurveType) (elliptic.Curve, error) {
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
