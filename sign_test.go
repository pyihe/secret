package secret

import (
	"crypto"
	"crypto/dsa"
	"testing"
)

type user struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
	ID   int    `json:"id"`
}

var (
	signer = NewSigner()
	dataStr    = "你可爱吗？000000"
	dataStruct = &user{
		Name: "ecc",
		Age:  1,
		ID:   1,
	}
)
func TestMyCipher_GenerateEccKey(t *testing.T) {
	priFile, pubFile, err := signer.GenerateECCKey(ECCCurveTypeP224, "./conf")
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%s\t%s\n", priFile, pubFile)
}

func TestAsyCipher_EccSignToBytes(t *testing.T) {
	if err := signer.SetECCKey("conf/ecPrivate.pem"); err != nil {
		t.Fatalf("%v\n", err)
	}
	signData, err := signer.EccSignToBytes(dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	ok, err := signer.EccVerify(signData, dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%v\n", ok)
}

func TestAsyCipher_EccSignToString(t *testing.T) {
	if err := signer.SetECCKey("conf/ecPrivate.pem"); err != nil {
		t.Fatalf("%v\n", err)
	}
	signData, err := signer.EccSignToString(dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	ok, err := signer.EccVerify(signData, dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%v\n", ok)
}

func TestMySigner_DSASignToString(t *testing.T) {
	err := signer.GenerateDSAKey(dsa.L1024N160)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	result, err := signer.DSASignToString(dataStr, crypto.SHA512)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("result = %s\n", result)
	ok , err := signer.DSAVerify(dataStr, result, crypto.SHA512)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%v\n", ok)
}

func TestMySigner_Ed25519SignToString(t *testing.T) {
	result, err := signer.Ed25519SignToString(dataStruct)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("result = %s\n", result)
	ok,err := signer.Ed25519Verify(dataStruct, result)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%v\n", ok)
}