package secret

import (
	"crypto"
	"testing"
)

type user struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
	ID   int    `json:"id"`
}

var (
	dataStr    = "你可爱吗？000000"
	dataStruct = &user{
		Name: "ecc",
		Age:  1,
		ID:   1,
	}
)
func TestMyCipher_GenerateEccKey(t *testing.T) {
	priFile, pubFile, err := r.GenerateEccKey(ECCCurveTypeP224, "./conf")
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%s\t%s\n", priFile, pubFile)
}

func TestAsyCipher_EccSignToBytes(t *testing.T) {
	if err := r.SetECCKey("conf/ecPrivate.pem"); err != nil {
		t.Fatalf("%v\n", err)
	}
	signData, err := r.EccSignToBytes(dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	ok, err := r.EccVerifySignBytes(signData, dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%v\n", ok)
}

func TestAsyCipher_EccSignToString(t *testing.T) {
	if err := r.SetECCKey("conf/ecPrivate.pem"); err != nil {
		t.Fatalf("%v\n", err)
	}
	signData, err := r.EccSignToString(dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	ok, err := r.EccVerifySignString(signData, dataStruct, crypto.SHA256)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	t.Logf("%v\n", ok)
}
