package secret

import (
	"fmt"
	"testing"
)

var (
	s = NewCipher()
	//key  = []byte("abcd0987")
	//key = []byte("abcd0987abcd0987abcd0987")
	key = []byte("abcd0987abcd0987")

	req = &SymRequest{
		PlainData:   dataStr,
		CipherData:  nil,
		Key:         key,
		Type:        SymTypeAES,
		ModeType:    BlockModeGCM,
		PaddingType: PaddingTypeNoPadding,
		AddData:     nil,
	}
)

func TestMyCipher_SymEncryptToBytes(t *testing.T) {
	t.Logf("原始数据为: %s\n", dataStr)
	d, err := s.SymEncryptToBytes(req)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("加密后的数据为: %s\n", d)
	req.CipherData = d
	d, err = s.SymDecrypt(req)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("解密后的数据为: %s\n", d)
}

func TestMyCipher_SymEncryptToString(t *testing.T) {
	t.Logf("原始数据为: %s\n", dataStr)
	d1, err := s.SymEncryptToString(req)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("加密后的数据为: %s\n", d1)
	req.CipherData = d1
	d2, err := s.SymDecrypt(req)
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Logf("解密后的数据为: %s\n", d2)
}

func TestMyCipher_RC4EncryptToBytes(t *testing.T) {
	d, err := s.RC4EncryptToBytes(dataStr, []byte(key))
	fmt.Println(string(d), err)

	d, err = s.RC4Decrypt(d, key)
	fmt.Printf("%s %v\n", d, err)
}

func TestMyCipher_RC4EncryptToString(t *testing.T) {
	fmt.Printf("原始数据为: %v\n", dataStr)
	d, err := s.RC4EncryptToString(dataStr, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("加密后的数据为: %v\n", d)

	result, err := s.RC4Decrypt(d, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("解密后的数据为: %s\n", result)
}
