package secret

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"hash"
	"secret/pkg"
)

type myHasher struct {
}

func NewHasher() Hasher {
	return new(myHasher)
}

//hexTag 标示字符串是否是16进制格式的
func (s *myHasher) HashToString(data interface{}, hashType crypto.Hash) (hashString string, err error) {
	var h hash.Hash
	h, err = getHashInstance(hashType)
	if err != nil {
		return
	}
	var bytes []byte
	bytes, err = getBytes(data)
	if err != nil {
		return
	}
	h.Write(bytes)
	hashBytes := h.Sum(nil)
	hashString = hex.EncodeToString(hashBytes)
	return
}

func (s *myHasher) HashToBytes(data interface{}, hashType crypto.Hash) (hashBytes []byte, err error) {
	var h hash.Hash
	h, err = getHashInstance(hashType)
	if err != nil {
		return
	}
	var bytes []byte
	bytes, err = getBytes(data)
	if err != nil {
		return
	}
	h.Write(bytes)
	hashBytes = h.Sum(nil)
	return
}

func (s *myHasher) DoubleHashToString(data interface{}, hashType crypto.Hash) (hashString string, err error) {
	var h hash.Hash
	h, err = getHashInstance(hashType)
	if err != nil {
		return
	}
	var bytes []byte
	bytes, err = getBytes(data)
	if err != nil {
		return
	}
	h.Write(bytes)
	hashBytes := h.Sum(nil)
	h.Reset()
	h.Write(hashBytes)
	hashBytes = h.Sum(nil)
	hashString = hex.EncodeToString(hashBytes)
	return
}

func (s *myHasher) DoubleHashToBytes(data interface{}, hashType crypto.Hash) (hashBytes []byte, err error) {
	var h hash.Hash
	h, err = getHashInstance(hashType)
	if err != nil {
		return
	}
	var bytes []byte
	bytes, err = getBytes(data)
	if err != nil {
		return
	}
	h.Write(bytes)
	hashBytes = h.Sum(nil)
	h.Reset()
	h.Write(hashBytes)
	hashBytes = h.Sum(nil)
	return
}

func getHashInstance(hashType crypto.Hash) (hash.Hash, error) {
	var h hash.Hash
	var err error
	switch hashType {
	case crypto.MD4:
		h = md4.New()
	case crypto.MD5:
		h = md5.New()
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA224:
		h = sha256.New224()
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha3.New384()
	case crypto.SHA512:
		h = sha512.New()
	case crypto.RIPEMD160:
		h = ripemd160.New()
	case crypto.SHA3_224:
		h = sha3.New224()
	case crypto.SHA3_256:
		h = sha3.New256()
	case crypto.SHA3_384:
		h = sha3.New384()
	case crypto.SHA3_512:
		h = sha3.New512()
	case crypto.SHA512_224:
		h = sha512.New512_224()
	case crypto.SHA512_256:
		h = sha512.New512_256()
	default:
		err = pkg.ErrInvalidHashType
	}
	return h, err
}

func getBytes(data interface{}) (bytes []byte, err error) {
	switch t := data.(type) {
	case string:
		bytes = []byte(t)
	case []byte:
		bytes = t
	default:
		bytes, err = json.Marshal(t)
	}
	return
}
