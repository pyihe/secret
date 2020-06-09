package secret

import (
	"fmt"
	"testing"
)

var (
	s = NewSymCipher()
	//key  = []byte("abcd0987")
	//key = []byte("abcd0987abcd0987abcd0987")
	key = []byte("abcd0987abcd0987")
)

func TestSymCipher_SymEncryptToBytes(t *testing.T) {
	t.Logf("原始数据为: %s\n", dataStr)
	d, err := s.SymEncryptToBytes(dataStr, key, SymTypeAES, BlockModeECB, PaddingTypeZeros)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("加密后的数据为: %s\n", d)
	d, err = s.SymDecryptBytes(d, key, SymTypeAES, BlockModeECB, PaddingTypeZeros)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("解密后的数据为: %s\n", d)
}

func TestSymCipher_SymEncryptToString(t *testing.T) {
	t.Logf("原始数据为: %s\n", dataStr)
	d1, err := s.SymEncryptToString(dataStr, key, SymTypeAES, BlockModeOFB, PaddingTypePKCS5)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("加密后的数据为: %s\n", d1)
	d2, err := s.SymDecryptString(d1, key, SymTypeAES, BlockModeOFB, PaddingTypePKCS5)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("解密后的数据为: %s\n", d2)
}

func TestSymCipher_RC4EncryptToBytes(t *testing.T) {
	d, err := s.RC4EncryptToBytes(dataStr, []byte(key))
	fmt.Println(string(d), err)

	d, err = s.RC4DecryptBytes(d, key)
	fmt.Printf("%s %v\n", d, err)
}

func TestSymCipher_RC4EncryptToString(t *testing.T) {
	fmt.Printf("原始数据为: %v\n", dataStr)
	d, err := s.RC4EncryptToString(dataStr, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("加密后的数据为: %v\n", d)

	result, err := s.RC4DecryptString(d, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("解密后的数据为: %s\n", result)
}
