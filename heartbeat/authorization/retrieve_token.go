// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package authorization

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
)

// Handles the response from the Authorization-Server and parses the data
func retrieveTokenFromServer(authConfig *Authorization) (*AuthorizationToken, string, error) {
	response, err, status := sendRequest(&authConfig.config)

	if err != nil && status == Unauthorized { // There was an error creating a request
		return nil, status, err
	} else if err != nil && status == Undefined { // There was an error while sending the request
		return nil, Error, err
	}
	defer response.Body.Close()

	if 400 <= response.StatusCode && response.StatusCode <= 499 { // Client Error
		return nil, Unauthorized, err
	} else if 500 <= response.StatusCode { // Server error
		return nil, Error, err
	}

	data, err := parseResponseBodyToMap(response.Body)
	if err != nil {
		return nil, Error, err
	}

	access_token, refresh_token, access_duration := extractResponseBody(*data)

	if access_duration == 0 {
		access_duration = authConfig.config.TokenExpireTime
	}

	return newAuthorizationToken(access_token, refresh_token, access_duration), Ok, nil

}

func sendRequest(config *OAuth) (*http.Response, error, string) {
	client := &http.Client{}
	if config.AuthString != "" { // String
		if req, err := http.NewRequest("POST", config.Url, bytes.NewBuffer([]byte(config.AuthString))); err == nil {
			logp.Info("Requesting a new Token with a String as Body")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			response, err := client.Do(req)
			return response, err, Undefined
		} else {
			return nil, errors.New(fmt.Sprintf("Unable to send a request to %s ", config.Url)), Unauthorized
		}
	} else if config.AuthBody != nil { // JSON
		payloadBuf := new(bytes.Buffer)
		json.NewEncoder(payloadBuf).Encode(config.AuthBody)
		if req, err := http.NewRequest("POST", config.Url, payloadBuf); err == nil {
			logp.Info("Requesting a new Token with a JSON-Body")
			req.Header.Set("Content-Type", "application/json")

			response, err := client.Do(req)
			return response, err, Undefined
		} else {
			return nil, errors.New(fmt.Sprintf("Unable to send a request to %s ", config.Url)), Unauthorized
		}
	}

	return nil, errors.New("No Authorization-Body defined."), Unauthorized
}

// Transforms the JSON-Body of a http Request to a map
func parseResponseBodyToMap(response io.ReadCloser) (*map[string]interface{}, error) {
	var data map[string]interface{}
	bodyBytes, parseErr := io.ReadAll(response)
	if parseErr != nil {
		return nil, errors.New("Unable to parse the Response from the Authorization-Server. Response must be a JSON.")
	}

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, errors.New("Unable to parse the Response from the Authorization-Server. Response must be a JSON.")
	}

	return &data, nil
}

// Fields for the response are defined in the RFC 6749 https://datatracker.ietf.org/doc/html/rfc6749
// If a field is not in the response, then Ignore that field and let the rest of the code handle it.
func extractResponseBody(body map[string]interface{}) (string, string, int) {
	var access_token, refresh_token string
	var access_duration int

	if body["access_token"] != nil {
		access_token = body["access_token"].(string)
	}
	if body["refresh_token"] != nil {
		refresh_token = body["refresh_token"].(string)
	}
	if body["expires_in"] != nil {
		access_duration = int(body["expires_in"].(float64))
	}

	return access_token, refresh_token, access_duration
}

func retrySendRequest(auth *Authorization) {
	duration := time.Duration(auth.config.RetryTime)
	time.Sleep(duration * time.Second)

	token, status, err := retrieveTokenFromServer(auth)

	auth.status = status
	if status == Error {
		go retrySendRequest(auth)
	}

	if err != nil {
		logp.Warn(fmt.Sprint(err))
	}

	if status == Ok && token != nil {
		auth.status = status
		auth.token = *token
	}
}
