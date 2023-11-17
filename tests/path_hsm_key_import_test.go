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

package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	testHelpers "securosys.ch/test-helpers"
)

func TestIMPORTKey(t *testing.T) {
	testEnv, err := testHelpers.NewTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("add config", testEnv.AddConfig)

	t.Run("Test Creating IMPORT key = AES", func(t *testing.T) {
		now := time.Now().UTC()
		timeStr := fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02dZ", now.Year(), int(now.Month()), now.Day(), now.Hour(), now.Minute(), now.Second())
		err := testIMPORTKeyCreate(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"keyLabel":   "TEST_SECUROSYS_SECRETS_ENGINE_IMPORT_AES_" + timeStr,
			"attributes": `{"decrypt": true,"sign": false,"unwrap": true,"derive": true,"sensitive": false,"extractable": false,"modifiable": true,"copyable": false,"destroyable": true}`,
			"secretKey":  "SkBOY1JmVWpYbjJyNXU3eCFBJUQqRy1LYVBkU2dWa1k=",
			"algorithm":  "AES",
		}, "custom_import_aes")

		assert.NoError(t, err)

		err = testHelpers.TestKeyRead(t, testEnv.Backend, testEnv.Storage, map[string]interface{}{
			"baseLabel": "TEST_SECUROSYS_SECRETS_ENGINE_IMPORT_AES_" + timeStr,
			"algorithm": "AES",
			"keySize":   256,
		}, "custom_import_aes")
		if err != nil {
			testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_import_aes")
		}
		assert.NoError(t, err)

		err = testHelpers.TestKeyDelete(t, testEnv.Backend, testEnv.Storage, "custom_import_aes")

		assert.NoError(t, err)
	})
}

func testIMPORTKeyCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}, keyName string) error {
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/" + keyName + "/import",
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
