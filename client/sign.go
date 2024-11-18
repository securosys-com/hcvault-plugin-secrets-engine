/*
Copyright (c) 2023 Securosys SA, authors: Tomasz Madej, Mikolaj Szargut

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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	helpers "securosys.ch/helpers"
)

// Function thats sends sign request to TSB
func (c *TSBClient) Sign(label string, password string, payload string, payloadType string, signatureAlgorithm string) (*helpers.SignatureResponse, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"signRequest": {
		  "payload": "` + payload + `",
		  "payloadType": "` + payloadType + `",
		  ` + passwordString + `
		  "signKeyName": "` + label + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/synchronousSign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return nil, code, errRes
	}
	var response helpers.SignatureResponse
	// response.KeyID = signKeyName
	// response.CertificateRequest = string(body)
	json.Unmarshal(body, &response)
	return &response, code, nil

}

// Function thats sends asynchronous sign request to TSB
func (c *TSBClient) AsyncSign(label string, password string, payload string, payloadType string, signatureAlgorithm string, customMetaData map[string]string) (string, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	var additionalMetaDataInfo map[string]string = make(map[string]string)

	metaDataB64, metaDataSignature, err := c.PrepareMetaData("Sign", additionalMetaDataInfo, customMetaData)
	if err != nil {
		return "", 500, err
	}
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"keyPassword": ` + string(charsPasswordJson) + `,`

	}
	metaDataSignatureString := "null"
	if metaDataSignature != nil {
		metaDataSignatureString = `"` + *metaDataSignature + `"`

	}
	requestJson := `{
		"payload": "` + payload + `",
		"payloadType": "` + payloadType + `",
		` + passwordString + `
		"signKeyName": "` + label + `",
		"signatureAlgorithm": "` + signatureAlgorithm + `",
		"metaData": "` + metaDataB64 + `",
		"metaDataSignature": ` + metaDataSignatureString + `
	  }`
	var jsonStr = []byte(helpers.MinifyJson(`{
		"signRequest": ` + requestJson + `,
		"requestSignature":` + string(c.GenerateRequestSignature(requestJson)) + `
	  }`))

	req, err := http.NewRequest("POST", c.HostURL+"/v1/sign", bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return "", code, errRes
	}
	var result map[string]interface{}
	errJSON := json.Unmarshal(body, &result)
	if errJSON != nil {
		return "", code, errJSON
	}
	return result["signRequestId"].(string), code, nil

}

// Function thats sends verify request to TSB
func (c *TSBClient) Verify(label string, password string, payload string, signatureAlgorithm string, signature string) (bool, int, error) {
	charsPasswordJson, _ := json.Marshal(helpers.StringToCharArray(password))
	passwordString := ""
	if len(charsPasswordJson) > 2 {
		passwordString = `"masterKeyPassword": ` + string(charsPasswordJson) + `,`

	}

	var jsonStr = []byte(`{
		"verifySignatureRequest": {
		  "payload": "` + payload + `",
		  ` + passwordString + `	
		  "signKeyName": "` + label + `",
		  "signatureAlgorithm": "` + signatureAlgorithm + `",
		  "signature": "` + signature + `"
		}
	  }`)

	req, err := http.NewRequest("POST", c.HostURL+"/v1/verify", bytes.NewBuffer(jsonStr))
	if err != nil {
		return false, 500, err
	}
	body, code, errRes := c.doRequest(req, KeyOperationTokenName)
	if errRes != nil {
		return false, code, errRes
	}
	var response map[string]interface{}
	json.Unmarshal(body, &response)
	if !helpers.ContainsKey(response, "signatureValid") {
		return false, 500, fmt.Errorf("error on verify response, need signatureValid, found %s", string(body[:]))
	}
	return response["signatureValid"].(bool), code, nil

}
