package pkg

import "errors"

var (
	ErrInvalidRequest     = errors.New("invalid request")
	ErrNoPrivateKey       = errors.New("not found key")
	ErrInvalidPKCSLevel   = errors.New("nonsupport PKCS level")
	ErrInvalidRSAType     = errors.New("nonsupport rsa type")
	ErrInvalidSignType    = errors.New("nonsupport sign type")
	ErrInvalidHashType    = errors.New("nonsupport hash type")
	ErrInvalidEncryptType = errors.New("nonsupport encrypt type")
	ErrInvalidEccType     = errors.New("nonsupport curve type")
	ErrInvalidBlockMode   = errors.New("invalid block mode")
	ErrDataInvalidBytes   = errors.New("sign bytes err")
	ErrPemReadFail        = errors.New("pem read fail")
	ErrInvalidCipherText  = errors.New("invalid cipher data type")
	ErrInvalidNonce       = errors.New("invalid nonce for gcm")
	ErrPaddingType        = errors.New("please check your padding type")
	ErrNoKey              = errors.New("key is empty")
	ErrNoCipher           = errors.New("data is empty")
)
