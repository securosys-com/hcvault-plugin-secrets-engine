/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.
*/

package testHelpers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
	"securosys.ch/backend"
)

type TestEnv struct {
	Backend logical.Backend
	Context context.Context
	Storage logical.Storage
	Conf    logical.BackendConfig
}

var keyPair *rsa.PrivateKey = nil

// Function checking that 2 variables are equals
func AreEqual(x, y interface{}) (bool, error) {
	xv := reflect.ValueOf(x)
	yv := reflect.ValueOf(y)
	if yv.Type().ConvertibleTo(xv.Type()) {
		return xv.Interface() == yv.Convert(xv.Type()).Interface(), nil
	} else {
		return false, errors.New("Types are mismatched")
	}
}
func InitRSAKeyPair() {
	keyPair, _ = rsa.GenerateKey(rand.Reader, 2048)
}
func Sign(data []byte) string {
	msgHash := sha256.New()
	msgHash.Write(data)
	msgHashSum := msgHash.Sum(nil)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, keyPair, crypto.SHA256, msgHashSum)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return signatureBase64
}
func GetPublicKey() string {
	pub := keyPair.Public()
	asn1Bytes, _ := x509.MarshalPKIXPublicKey(pub)
	// Encode private key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		},
	)
	publicKey := string(pubPEM[:])
	publicKey = strings.Replace(publicKey, "-----BEGIN PUBLIC KEY-----", "", 1)
	publicKey = strings.Replace(publicKey, "-----END PUBLIC KEY-----", "", 1)
	publicKey = strings.Replace(publicKey, "\n", "", 20)
	return publicKey
}

// This function create initialized test environment with storage in memory
func NewTestEnv() (*TestEnv, error) {
	ctx := context.Background()

	maxLease, _ := time.ParseDuration("99999s")
	defaultLease, _ := time.ParseDuration("88888s")
	conf := &logical.BackendConfig{
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLease,
			MaxLeaseTTLVal:     maxLease,
		},
		Logger: logging.NewVaultLogger(log.Debug),
	}
	b, err := backend.Factory(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &TestEnv{
		Backend: b,
		Context: ctx,
		Conf:    *conf,
		Storage: &logical.InmemStorage{},
	}, nil
}

// Function initialize configuration needed by all functions/operations on keys in TSB
func (e *TestEnv) AddConfig(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   e.Storage,
		Data:      ConfigParams,
	}
	_, err := e.Backend.HandleRequest(e.Context, req)
	require.Nil(t, err)
}

// Function prepare some test keys
func (e *TestEnv) PrepareTestKeys(t *testing.T) {
	InitRSAKeyPair()
	now := time.Now().UTC()
	timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
	_, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/aes/test_aes_256",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_AES_256_" + timeStr,
			"keySize":    256,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/aes/test_aes_256_rotate",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_AES_256_ROTATE_" + timeStr,
			"keySize":    256,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/aes/test_aes_128",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_AES_128_" + timeStr,
			"keySize":    128,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/bls/test_bls",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_BLS_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/camellia/test_camellia",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_CAMELLIA_" + timeStr,
			"keySize":    256,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/chacha20/test_chacha20",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_CHACHA20_" + timeStr,
			"keySize":    256,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/dsa/test_dsa_1024",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_DSA_1024_" + timeStr,
			"keySize":    1024,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/ec/test_ec_secp256k1",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_EC_secp256k1_" + timeStr,
			"curveOid":   "1.3.132.0.10",
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/ed/test_ed_ed25519",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_ED_Ed25519_" + timeStr,
			"curveOid":   "1.3.101.112",
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/tdea/test_tdea",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TDEA_" + timeStr,
			"keySize":    0,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": true,"sensitive": false,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}

	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/rsa/test_rsa_2048_pass",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_PASS_" + timeStr,
			"keySize":    2048,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/rsa/test_rsa_2048",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_" + timeStr,
			"keySize":    2048,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": true,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/rsa/test_rsa_2048_modify",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_MODIFY_" + timeStr,
			"keySize":    1024,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/rsa/test_rsa_2048_policy",
		Data: map[string]interface{}{
			"keyLabel":     "TEST_SECUROSYS_SECRETS_ENGINE_RSA_2048_POLICY_" + timeStr,
			"keySize":      2048,
			"attributes":   `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			"simplePolicy": `{"Tomasz Madej":"` + GetPublicKey() + `"}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	//Create key using Hashicorp Vault Key Management key types
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/aes256-gcm96/type_aes",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_AES_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/rsa-2048/type_rsa_2048",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_RSA_2048_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/rsa-3072/type_rsa_3072",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_RSA_3072_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/rsa-4096/type_rsa_4096",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_RSA_4096_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/ecdsa-p256/type_ec_p256",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_EC_P256_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/ecdsa-p384/type_ec_p384",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_EC_P384_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/type/ecdsa-p521/type_ec_p521",
		Data: map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_TYPE_EC_P521_" + timeStr,
			"attributes": `{"decrypt": true,"sign": true,"unwrap": true,"derive": false,"sensitive": true,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
		},
		Storage: e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}

}

// Function deletes test keys
func (e *TestEnv) RemoveTestKeys(t *testing.T) {
	_, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_aes_256",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_aes_256_rotate",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_aes_128",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_bls",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_camellia",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_chacha20",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)

	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_dsa_1024",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_ec_secp256k1",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_ed_ed25519",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	_, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_tdea",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)

	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_rsa_2048",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_rsa_2048_modify",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_rsa_2048_pass",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test_rsa_2048_policy",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/type_aes",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/type_rsa_2048",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/type_rsa_3072",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/type_rsa_4096",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/type_ec_p256",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/type_ec_p384",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}
	time.Sleep(1000)
	e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/type_ec_p521",
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   e.Storage,
	})
	if err != nil {
		fmt.Println(err.Error())
	}

}

// Function preparing a testing backend system
func GetTestBackend(tb testing.TB) (*backend.SecurosysBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()

	b, err := backend.Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*backend.SecurosysBackend), config.StorageView
}

// Function thats make a request for delete key operation
func TestKeyDelete(t *testing.T, b logical.Backend, s logical.Storage, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/" + keyName,
		Data:      map[string]interface{}{"removeFromHSM": true},
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

// Function thats make a request for create key operation
func TestKeyCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, keyName string, keyType string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/" + keyType + "/" + keyName,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return fmt.Errorf(err.Error())
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

// Function thats make a request for reading key xml data
func TestKeyReadXML(t *testing.T, b logical.Backend, s logical.Storage, expected []string, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + keyName + "/xml",
		Storage:   s,
	})

	if err != nil {
		return err
	}
	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	for _, expectedV := range expected {
		actualV, ok := resp.Data[expectedV]
		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output`, expectedV, expectedV)
		}
		if actualV == "" || actualV == nil {
			return fmt.Errorf(`expected data["%s"] = is not empty`, expectedV)
		}
	}

	return nil
}

// Function thats make a request for reading key data
func TestKeyRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/" + keyName,
		Storage:   s,
	})

	if err != nil {
		return err
	}
	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	for k, expectedV := range expected {
		actualV, ok := resp.Data[k]
		if !ok {
			return fmt.Errorf(`expected data["%s"] = %v but was not included in read output`, k, expectedV)
		}
		result, err := AreEqual(expectedV, actualV)
		if err != nil {
			return fmt.Errorf(`unexpected error: %s`, err.Error())
		}
		if !result {
			return fmt.Errorf(`expected data["%s"] = %v, instead got %v`, k, expectedV, actualV)
		}
	}

	return nil
}
