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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// HostURL - Default Securosys TSB URL
const HostURL string = ""

// TSBClient struct
type TestTSBClient struct {
	HostURL    string
	HTTPClient *http.Client
}

// Function inicialize new client for accessing TSB
func NewTestTSBClient() (*TestTSBClient, error) {
	c := TestTSBClient{
		HTTPClient: &http.Client{Timeout: 9999999 * time.Second},
		// Default Hashicups URL
		HostURL: ConfigParams["restapi"].(string),
	}

	return &c, nil
}

// Function thats send request modify key to TSB

func (c *TestTSBClient) GetApprovalTasks(taskType string) (string, string, error) {
	path := ""
	switch taskType {
	case "Block":
		path = "/v1/filteredBlockKeyApprovalTask"
	case "Decrypt":
		path = "/v1/filteredDecryptApprovalTask"
	case "Modify":
		path = "/v1/filteredModifyKeyApprovalTask"
	case "Sign":
		path = "/v1/filteredSignApprovalTask"
	case "UnBlock":
		path = "/v1/filteredUnblockKeyApprovalTask"
	case "UnWrap":
		path = "/v1/filteredUnwrapKeyApprovalTask"
	}
	now := time.Now()

	// Convert the time to UTC
	utc := now.UTC()

	// Format the time using the same layout as JavaScript's toISOString()
	iso8601 := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
		utc.Year(), utc.Month(), utc.Day(),
		utc.Hour(), utc.Minute(), utc.Second(), utc.Nanosecond()/1e6)

	var jsonStr = []byte(`{
		"timestamp":"` + iso8601 + `",
		"timestampSignature":"` + Sign([]byte(iso8601)) + `",
		"approverPublicKey":"` + GetPublicKey() + `",
		"detailLevel": "level5",
		"timestampDigestAlgorithm":"SHA-256",
		"paging": {
            "pageNumber": 0,
            "pageSize": 25,
		"sortOrder": "CREATION_DATE_ASC"
	}}`)
	req, err := http.NewRequest("POST", c.HostURL+path, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", "", err
	}
	body, err, _ := c.doRequest(req)
	var result map[string]interface{}
	_ = json.Unmarshal(body, &result)
	if err != nil {
		return "", "", err
	}
	tasks := result["tasks"].([]interface{})
	task := tasks[0].(map[string]interface{})
	id := task["id"].(string)
	approvalToBeSigned := task["approvalToBeSigned"].(string)
	return id, approvalToBeSigned, nil
}
func (c *TestTSBClient) MakeApproval(id string, approvalToBeSigned string) (bool, error) {
	// Format the time using the same layout as JavaScript's toISOString()
	data, _ := base64.StdEncoding.DecodeString(approvalToBeSigned)
	var jsonStr = []byte(`{
		"signature":"` + Sign(data) + `",
		"approvalDigestAlgorithm":"SHA-256",
		"approverPublicKey":"` + GetPublicKey() + `",
		"approvalToBeSigned":"` + approvalToBeSigned + `",
		"id":"` + id + `"}`)
	req, err := http.NewRequest("POST", c.HostURL+"/v1/approval", bytes.NewBuffer(jsonStr))
	if err != nil {
		return false, err
	}
	_, err, code := c.doRequest(req)
	if err != nil {
		return false, err
	}
	if code == 200 {
		return true, nil
	} else {
		return false, fmt.Errorf("Wrong result code. Expected 200 got %d", code)
	}
}

// Function that making all requests. Using config for Authorization to TSB
func (c *TestTSBClient) doRequest(req *http.Request) ([]byte, error, int) {
	// req.Header.Set("Authorization", c.Token)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err, res.StatusCode
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err, res.StatusCode
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return body, fmt.Errorf("status: %d, body: %s", res.StatusCode, body), res.StatusCode
	}

	return body, err, res.StatusCode
}
