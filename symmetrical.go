package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/base64"
	"secret/pkg"
)

/*
	对称加密
*/

const (
	SymTypeDES symType = iota + 1
	SymTypeTripleDes
	SymTypeAES
)

const (
	BlockModeECB blockMode = iota + 1
	BlockModeCBC
	BlockModeCFB
	BlockModeOFB
	BlockModeCTR
)

var (
	defaultSymCipher = &symCipher{}
)

type (
	symType   uint
	blockMode uint

	symCipher struct {
	}
)

func NewSymCipher() SymCipher {
	return defaultSymCipher
}

func (s *symCipher) RC4EncryptToBytes(data interface{}, key []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var bytes []byte
	bytes, err = getBytes(data)
	if err != nil {
		return nil, err
	}
	var dst = make([]byte, len(bytes))
	c.XORKeyStream(dst, bytes)
	return dst, nil
}

func (s *symCipher) RC4EncryptToString(data interface{}, key []byte) (string, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}
	var bytes []byte
	bytes, err = getBytes(data)
	if err != nil {
		return "", err
	}
	var dst = make([]byte, len(bytes))
	c.XORKeyStream(dst, bytes)
	result := base64.StdEncoding.EncodeToString(dst)
	return result, nil
}

func (s *symCipher) RC4DecryptBytes(encryptData, key []byte) ([]byte, error) {
	return s.RC4EncryptToBytes(encryptData, key)
}

func (s *symCipher) RC4DecryptString(encryptData string, key []byte) ([]byte, error) {
	bytes, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, err
	}
	return s.RC4EncryptToBytes(bytes, key)
}

//对称加密，返回字节切片
func (s *symCipher) SymEncryptToBytes(data interface{}, key []byte, encryptType symType, modeType blockMode, paddingType paddingType) (encryptData []byte, err error) {
	/*
		1. 创建密码器
		2. 填充明文
		3. 加密模式选择: ECB, CBC, CFB, OFB
		4. 对填充数据加密
	*/
	var originalData []byte
	originalData, err = getBytes(data)
	if err != nil {
		return
	}
	var block cipher.Block
	switch encryptType {
	case SymTypeDES:
		block, err = des.NewCipher(key)
	case SymTypeTripleDes:
		block, err = des.NewTripleDESCipher(key)
	case SymTypeAES:
		block, err = aes.NewCipher(key)
	default:
		err = pkg.ErrInvalidEncryptType
	}
	if err != nil {
		return
	}

	//填充
	blockSize := block.BlockSize()
	originalData = padding(originalData, blockSize, paddingType)

	//加密模式选择: ECB, CBC, CFB, OFB
	encryptData = make([]byte, len(originalData))
	switch modeType {
	case BlockModeECB:
		var temp = encryptData
		for len(originalData) > 0 {
			block.Encrypt(temp, originalData[:blockSize])
			originalData = originalData[blockSize:]
			temp = temp[blockSize:]
		}
	case BlockModeCBC:
		blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
		blockMode.CryptBlocks(encryptData, originalData)
	case BlockModeCFB:
		blockStream := cipher.NewCFBEncrypter(block, key[:blockSize])
		blockStream.XORKeyStream(encryptData, originalData)
	case BlockModeOFB:
		stream := cipher.NewOFB(block, key[:blockSize])
		stream.XORKeyStream(encryptData, originalData)
	case BlockModeCTR:
		stream := cipher.NewCTR(block, key[:blockSize])
		stream.XORKeyStream(encryptData, originalData)
	default:
		err = pkg.ErrInvalidBlockMode
	}
	return
}

//对称加密，返回base64编码后的字符串
func (s *symCipher) SymEncryptToString(originalData interface{}, key []byte, encryptType symType, modeType blockMode, paddingType paddingType) (encryptString string, err error) {
	var data []byte
	data, err = getBytes(originalData)
	if err != nil {
		return
	}
	encryptData, err := s.SymEncryptToBytes(data, key, encryptType, modeType, paddingType)
	if err != nil {
		return "", err
	}
	encryptString = base64.StdEncoding.EncodeToString(encryptData)
	return
}

//解密
func (s *symCipher) SymDecryptBytes(encryptData, key []byte, t symType, modeType blockMode, paddingType paddingType) (originalData []byte, err error) {
	/*
		1. 创建密码器
		2. 实例话解密模式
		3. 解密
		4. 去填充
	*/
	var block cipher.Block
	switch t {
	case SymTypeDES:
		block, err = des.NewCipher(key)
	case SymTypeTripleDes:
		block, err = des.NewTripleDESCipher(key)
	case SymTypeAES:
		block, err = aes.NewCipher(key)
	default:
		err = pkg.ErrInvalidEncryptType
	}
	if err != nil {
		return
	}
	blockSize := block.BlockSize()
	originalData = make([]byte, len(encryptData))

	switch modeType {
	case BlockModeECB:
		temp := originalData
		for len(encryptData) > 0 {
			block.Decrypt(temp, encryptData[:blockSize])
			encryptData = encryptData[blockSize:]
			temp = temp[blockSize:]
		}
	case BlockModeCBC:
		blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
		blockMode.CryptBlocks(originalData, encryptData)
	case BlockModeOFB:
		stream := cipher.NewOFB(block, key[:blockSize])
		stream.XORKeyStream(originalData, encryptData)
	case BlockModeCFB:
		blockStream := cipher.NewCFBDecrypter(block, key[:blockSize])
		blockStream.XORKeyStream(originalData, encryptData)
	case BlockModeCTR:
		stream := cipher.NewCTR(block, key[:blockSize])
		stream.XORKeyStream(originalData, encryptData)
	default:
		err = pkg.ErrInvalidBlockMode
	}
	//去填充
	originalData = unPadding(originalData, paddingType)
	return
}

func (s *symCipher) SymDecryptString(encryptData string, key []byte, t symType, modeType blockMode, paddingType paddingType) (originalData []byte, err error) {
	data, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, err
	}
	return s.SymDecryptBytes(data, key, t, modeType, paddingType)
}
