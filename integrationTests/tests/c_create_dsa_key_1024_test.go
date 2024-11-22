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

package integrationTests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/hashicorp/vault-client-go"
	"github.com/stretchr/testify/assert"
	integrationClient "securosys.ch/integration/client"
)

func TestCreateDSAKey1024Plugin(t *testing.T) {

	t.Run("C.1 Test Create Key DSA Key with name integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/dsa/integration_test_key_dsa_1024", map[string]interface{}{
			"keyLabel": "integrationTestKeyDSA_1024",
			"keySize":  1024,
			"attributes": `{
				"decrypt": true,
				"sign": false,
				"unwrap": true,
				"derive": true,
				"sensitive": false,
				"alwaysSensitive": false,
				"extractable": true,
				"neverExtractable": true,
				"modifiable": true,
				"copyable": false,
				"destroyable": true
			}`,
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "DSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "DSA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyDSA_1024" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyDSA_1024", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("1024") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "1024", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyDSA_1024_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyDSA_1024_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.2 Test List Keys", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.List(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s", "null").Error())
		}
		if resp.Data["key_info"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s", "null").Error())

		}
		keyInfo := resp.Data["key_info"].(map[string]interface{})
		if keyInfo == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of keys got %s", "null").Error())
		}
		if keyInfo["integration_test_key_dsa_1024"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: integration_test_key_dsa_1024 got %s", "null").Error())
		}
	})
	t.Run("C.3 Read DSA Key with name integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "DSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "DSA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyDSA_1024" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyDSA_1024", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v1", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("1024") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "1024", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyDSA_1024_v1" {
			assert.FailNow(t, fmt.Errorf("Expected: Key label %s got %s", "integrationTestKeyDSA_1024_v1", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.4 Rotate DSA Key with name integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024/rotate", map[string]interface{}{})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		resp, _ := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024")
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "DSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "DSA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["baseLabel"].(string) != "integrationTestKeyDSA_1024" {
			assert.FailNow(t, fmt.Errorf("Expected: Key name %s got %s", "integrationTestKeyDSA_1024", resp.Data["baseLabel"]).Error())
		}
		if resp.Data["version"].(string) != "v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v2", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("1024") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "1024", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyDSA_1024_v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s", "integrationTestKeyDSA_1024_v2", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.5 Test List Versions of Key integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, err := client.List(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024")
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s", "null").Error())
		}
		if resp.Data["key_info"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s", "null").Error())

		}
		keyInfo := resp.Data["key_info"].(map[string]interface{})
		if keyInfo == nil {
			assert.FailNow(t, fmt.Errorf("Expected: List of key versions got %s", "null").Error())
		}
		if keyInfo["v1"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: v1 got %s", "null").Error())
		}
		if keyInfo["v2"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: v2 got %s", "null").Error())
		}
	})
	t.Run("C.6 Test List Versions of Key integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		resp, _ := client.Read(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024/v2")
		if resp == nil || resp.Data == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Key response got %s", "null").Error())
		}
		if resp.Data["algorithm"].(string) != "DSA" {
			assert.FailNow(t, fmt.Errorf("Expected: Key type %s got %s", "DSA", resp.Data["algorithm"]).Error())
		}
		if resp.Data["version"].(string) != "v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key version %s got %s", "v2", resp.Data["version"]).Error())
		}
		if resp.Data["keySize"].(json.Number) != json.Number("1024") {
			assert.FailNow(t, fmt.Errorf("Expected: Key size %s got %s", "1024", resp.Data["keySize"]).Error())
		}
		if resp.Data["keyLabel"].(string) != "integrationTestKeyDSA_1024_v2" {
			assert.FailNow(t, fmt.Errorf("Expected: Key Label %s got %s", "integrationTestKeyDSA_1024_v2", resp.Data["keyLabel"]).Error())
		}
	})
	t.Run("C.7 Export DSA Key with name integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		resp, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024/export", map[string]interface{}{})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
		if resp.Data["publicKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Public Key got %s", "null").Error())
		}
		if resp.Data["privateKey"] == nil {
			assert.FailNow(t, fmt.Errorf("Expected: Private Key got %s", "null").Error())
		}
	})
	t.Run("C.8 Update password DSA Key with name integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()

		_, err := client.Write(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024/update-password", map[string]interface{}{
			"password":    "",
			"newPassword": "test",
		})
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
	t.Run("C.9 Test Remove Key DSA Key with name integrationTestKeyDSA_1024", func(t *testing.T) {
		ctx := context.Background()

		client := integrationClient.InitVaultClient()
		_, err := client.Delete(ctx, integrationClient.VaultConfig.SecretsEnginePath+"/keys/integration_test_key_dsa_1024", vault.WithQueryParameters(url.Values{
			"removeFromHSM": {"true"},
		}))
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	})
}
