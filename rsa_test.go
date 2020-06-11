package secret

import (
	"crypto"
	"encoding/json"
	"testing"
)


func TestGenerateRSAKey(t *testing.T) {
	privateFile, publicFile, err := s.GenerateRSAKey(1024, "./conf", PKCSLevel1)
	if err != nil {
		t.Fatalf("err = %v\n", err)
	}
	t.Logf("%s\t%s\n", privateFile, publicFile)
}

func TestAsyCipher_RSAEncryptToBytes(t *testing.T) {
	err := s.SetRSAKey("./conf/private.pem", PKCSLevel1)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("before encrypt, plain text is: %v\n", dataStruct)
	label := []byte("this is label")
	encryptData, err := s.RSAEncryptToBytes(dataStruct, RSAEncryptTypePKCS1v15, label)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("after encrypt, cipher text is: %s\n", encryptData)
	originalData, err := s.RSADecrypt(encryptData, RSAEncryptTypePKCS1v15, label)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	var u user
	err = json.Unmarshal(originalData, &u)
	if err != nil {
		t.Fatalf("%v\n", err)
	} else {
		t.Logf("%v\n", u)
	}
	t.Logf("after decrypt, plain text: %s\n", originalData)
}

func TestAsyCipher_RSAEncryptToString(t *testing.T) {
	err := s.SetRSAKey("./conf/private.pem", PKCSLevel1)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("before encrypt, plain text is: %+v\n", dataStruct)
	encryptString, err := s.RSAEncryptToString(dataStruct, RSAEncryptTypeOAEP, nil)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("after encrypt, cipher text is: %s\n", encryptString)
	originalString, err := s.RSADecrypt(encryptString, RSAEncryptTypeOAEP, nil)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	var u user
	json.Unmarshal(originalString, &u)
	t.Logf("%+v\n", u)
	t.Logf("after decrypt, plain text is: %s\n", originalString)
}

func TestAsyCipher_RSASignToBytes(t *testing.T) {
	err := s.SetRSAKey("./conf/private.pem", PKCSLevel1)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("before sign, data is: %s\n", dataStr)
	signData, err := s.RSASignToBytes(dataStr, RSASignTypePSS, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("after sign, sign data is: %s\n", signData)
	ok, err := s.RSAVerify(signData, dataStr, RSASignTypePSS, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("verify result: %v\n", ok)
}

func TestAsyCipher_RSASignToString(t *testing.T) {
	err := s.SetRSAKey("./conf/private.pem", PKCSLevel1)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("before sign, data is: %s\n", dataStr)
	signData, err := s.RSASignToString(dataStr, RSASignTypePSS, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("after sign, sign data is: %s\n", signData)
	ok, err := s.RSAVerify(signData, dataStr, RSASignTypePSS, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("verify result: %v\n", ok)
}
