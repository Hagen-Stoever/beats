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
	"errors"
	"fmt"
	"net/http"

	"github.com/elastic/elastic-agent-libs/logp"
)

func refreshToken(auth *Authorization) {
	if auth.token.accessToken != "" && auth.config.RefreshTokenStructure != "" {
		token, err := retrieveRefreshTokenFromServer(auth)

		if err != nil { // Refresh Token failed, try new Token
			logp.Warn(err.Error())
			getTokenAndHandleStatus(auth)

		} else {
			auth.status = Ok
			auth.token.accessToken = token.accessToken
			auth.token.refreshToken = token.refreshToken
		}
	} else {
		getTokenAndHandleStatus(auth)
	}
}

func getTokenAndHandleStatus(auth *Authorization) {
	token, status, err := retrieveTokenFromServer(auth)
	auth.status = status

	if status == Ok {
		auth.token = *token
	} else if status == Error {
		logp.Warn(fmt.Sprintf("Could not retrieve a token at this time; Error:  %v", err))
	} else {
		logp.Warn("Unable to retrieve a token, Invalid Config and/or Authorization")
	}
}

// Handles the response from the Authorization-Server and parses the data
func retrieveRefreshTokenFromServer(auth *Authorization) (*AuthorizationToken, error) {
	response, err := sendRefreshTokenRequest(auth)

	if err != nil { // There was an error creating a request
		return nil, err
	}
	defer response.Body.Close()

	if 400 <= response.StatusCode { // Client Error
		return nil, errors.New(fmt.Sprintf("Authorization-Server responded with %s when trying to use refresh-token", response.Status))
	}

	data, err := parseResponseBodyToMap(response.Body)
	if err != nil {
		return nil, err
	}

	access_token, refresh_token, access_duration := extractResponseBody(*data)

	return newAuthorizationToken(access_token, refresh_token, access_duration), nil

}

func sendRefreshTokenRequest(auth *Authorization) (*http.Response, error) {
	client := &http.Client{}

	body := fmt.Sprintf(auth.config.RefreshTokenStructure, auth.token.refreshToken)

	if req, err := http.NewRequest("POST", auth.config.Url, bytes.NewBuffer([]byte(body))); err == nil {
		logp.Info("Requesting a new Token with a String as Body")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return client.Do(req)
	} else {
		return nil, errors.New("Unable to parse the refresh token")
	}
}
