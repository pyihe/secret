package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"crypto/rsa"
	"encoding/base64"
	"github.com/pyihe/secret/pkg"
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
	BlockModeGCM
)

type (
	symType   uint
	blockMode uint

	myCipher struct {
		rsaPrivateKey *rsa.PrivateKey //RSA密钥
		rsaPublicKey  *rsa.PublicKey  //RSA公钥
	}

	//对称加密消息请求
	SymRequest struct {
		PlainData   interface{} //明文，用于加密
		CipherData  interface{} //密文，用于解密，两种类型：[]byte或者string
		Key         []byte      //密钥
		Type        symType     //加密类型
		ModeType    blockMode   //分组方式
		PaddingType paddingType //填充方式
		Iv          []byte      //iv
		AddData     []byte      //GCM模式下额外的验证数据, 如果使用GCM模式, 需要将nonce传递给解密方
		Nonce       []byte      // GCM模式下的加密、解密随机向量
	}
)

func NewCipher() Cipher {
	return &myCipher{}
}

func (m *myCipher) RC4EncryptToBytes(data interface{}, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, pkg.ErrNoKey
	}
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

func (m *myCipher) RC4EncryptToString(data interface{}, key []byte) (string, error) {
	if len(key) == 0 {
		return "", pkg.ErrNoKey
	}
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

func (m *myCipher) RC4Decrypt(encryptData interface{}, key []byte) ([]byte, error) {
	var cipherText []byte
	var err error
	switch t := encryptData.(type) {
	case string:
		if len(t) == 0 {
			return nil, pkg.ErrNoCipher
		}
		cipherText, err = base64.StdEncoding.DecodeString(t)
		if err != nil {
			return nil, err
		}
	case []byte:
		if len(t) == 0 {
			return nil, pkg.ErrNoCipher
		}
		cipherText = t
	default:
		return nil, pkg.ErrInvalidCipherText
	}
	return m.RC4EncryptToBytes(cipherText, key)
}

//对称加密，返回字节切片
func (m *myCipher) SymEncryptToBytes(request *SymRequest) (encryptData []byte, err error) {
	/*
		1. 创建密码器
		2. 填充明文
		3. 加密模式选择: ECB, CBC, CFB, OFB
		4. 对填充数据加密
	*/
	if request == nil {
		err = pkg.ErrInvalidRequest
		return
	}
	if len(request.Key) == 0 {
		return nil, pkg.ErrNoKey
	}
	var originalData []byte
	originalData, err = getBytes(request.PlainData)
	if err != nil {
		return
	}
	var block cipher.Block
	switch request.Type {
	case SymTypeDES:
		block, err = des.NewCipher(request.Key)
	case SymTypeTripleDes:
		block, err = des.NewTripleDESCipher(request.Key)
	case SymTypeAES:
		block, err = aes.NewCipher(request.Key)
	default:
		err = pkg.ErrInvalidEncryptType
	}
	if err != nil {
		return
	}

	blockSize := block.BlockSize()
	if len(request.Iv) == 0 {
		request.Iv = request.Key[:blockSize]
	}

	//加密模式选择: ECB, CBC, CFB, OFB
	switch request.ModeType {
	case BlockModeECB:
		//填充
		if request.PaddingType != PaddingTypePKCS5 &&
			request.PaddingType != PaddingTypePKCS7 &&
			request.PaddingType != PaddingTypeZeros {
			err = pkg.ErrPaddingType
			return
		}
		originalData = padding(originalData, blockSize, request.PaddingType)
		encryptData = make([]byte, len(originalData))
		var temp = encryptData
		for len(originalData) > 0 {
			block.Encrypt(temp, originalData[:blockSize])
			originalData = originalData[blockSize:]
			temp = temp[blockSize:]
		}
	case BlockModeCBC:
		//填充
		if request.PaddingType != PaddingTypePKCS5 &&
			request.PaddingType != PaddingTypePKCS7 &&
			request.PaddingType != PaddingTypeZeros {
			err = pkg.ErrPaddingType
			return
		}
		originalData = padding(originalData, blockSize, request.PaddingType)
		encryptData = make([]byte, len(originalData))
		blockMode := cipher.NewCBCEncrypter(block, request.Iv)
		blockMode.CryptBlocks(encryptData, originalData)
	case BlockModeCFB:
		encryptData = make([]byte, len(originalData))
		blockStream := cipher.NewCFBEncrypter(block, request.Iv)
		blockStream.XORKeyStream(encryptData, originalData)
	case BlockModeOFB:
		encryptData = make([]byte, len(originalData))
		stream := cipher.NewOFB(block, request.Iv)
		stream.XORKeyStream(encryptData, originalData)
	case BlockModeCTR:
		encryptData = make([]byte, len(originalData))
		stream := cipher.NewCTR(block, request.Iv)
		stream.XORKeyStream(encryptData, originalData)
	case BlockModeGCM:
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		encryptData = gcm.Seal(nil, request.Nonce, originalData, request.AddData)
	default:
		err = pkg.ErrInvalidBlockMode
	}
	return
}

//对称加密，返回base64编码后的字符串
func (m *myCipher) SymEncryptToString(request *SymRequest) (encryptString string, err error) {
	encryptData, err := m.SymEncryptToBytes(request)
	if err != nil {
		return "", err
	}
	encryptString = base64.StdEncoding.EncodeToString(encryptData)
	return
}

//解密
func (m *myCipher) SymDecrypt(request *SymRequest) (originalData []byte, err error) {
	/*
		1. 创建密码器
		2. 实例话解密模式
		3. 解密
		4. 去填充
	*/
	if request == nil {
		err = pkg.ErrInvalidRequest
		return
	}
	if len(request.Key) == 0 {
		return nil, pkg.ErrNoKey
	}
	var encryptData []byte
	if request.CipherData == nil {
		return nil, pkg.ErrInvalidRequest
	}
	switch v := request.CipherData.(type) {
	case []byte:
		encryptData = v
	case string:
		encryptData, err = base64.StdEncoding.DecodeString(v)
		if err != nil {
			return
		}
	default:
		err = pkg.ErrInvalidCipherText
		return
	}

	var block cipher.Block
	switch request.Type {
	case SymTypeDES:
		block, err = des.NewCipher(request.Key)
	case SymTypeTripleDes:
		block, err = des.NewTripleDESCipher(request.Key)
	case SymTypeAES:
		block, err = aes.NewCipher(request.Key)
	default:
		err = pkg.ErrInvalidEncryptType
	}
	if err != nil {
		return
	}
	blockSize := block.BlockSize()
	if len(request.Iv) == 0 {
		request.Iv = request.Key[:blockSize]
	}
	originalData = make([]byte, len(encryptData))

	switch request.ModeType {
	case BlockModeECB:
		if request.PaddingType != PaddingTypePKCS5 &&
			request.PaddingType != PaddingTypePKCS7 &&
			request.PaddingType != PaddingTypeZeros {
			err = pkg.ErrPaddingType
			return
		}
		temp := originalData
		for len(encryptData) > 0 {
			block.Decrypt(temp, encryptData[:blockSize])
			encryptData = encryptData[blockSize:]
			temp = temp[blockSize:]
		}
		//去填充
		originalData = unPadding(originalData, request.PaddingType)
	case BlockModeCBC:
		if request.PaddingType != PaddingTypePKCS5 &&
			request.PaddingType != PaddingTypePKCS7 &&
			request.PaddingType != PaddingTypeZeros {
			err = pkg.ErrPaddingType
			return
		}
		blockMode := cipher.NewCBCDecrypter(block, request.Iv)
		blockMode.CryptBlocks(originalData, encryptData)
		//去填充
		originalData = unPadding(originalData, request.PaddingType)
	case BlockModeOFB:
		stream := cipher.NewOFB(block, request.Iv)
		stream.XORKeyStream(originalData, encryptData)
	case BlockModeCFB:
		blockStream := cipher.NewCFBDecrypter(block, request.Iv)
		blockStream.XORKeyStream(originalData, encryptData)
	case BlockModeCTR:
		stream := cipher.NewCTR(block, request.Iv)
		stream.XORKeyStream(originalData, encryptData)
	case BlockModeGCM:
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(block)
		if err != nil {
			return
		}
		originalData, err = gcm.Open(nil, request.Nonce, encryptData, request.AddData)
	default:
		err = pkg.ErrInvalidBlockMode
	}
	return
}
