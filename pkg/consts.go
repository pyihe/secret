package pkg

import "errors"

var (
	ErrNoPrivateKey       = errors.New("not found private key")
	ErrInvalidPKCSLevel   = errors.New("nonsupport PKCS level")
	ErrInvalidRSAType     = errors.New("nonsupport rsa type")
	ErrInvalidSignType    = errors.New("nonsupport sign type")
	ErrInvalidHashType    = errors.New("nonsupport hash type")
	ErrInvalidEncryptType = errors.New("nonsupport encrypt type")
	ErrInvalidEccType     = errors.New("nonsupport curve type")
	ErrInvalidBlockMode   = errors.New("invalid block mode")
	ErrDataInvalidBytes   = errors.New("sign bytes err")
	ErrPemReadFail        = errors.New("pem read fail")
)
