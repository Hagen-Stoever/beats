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
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent-libs/logp"
)

//
// This file handles the methods of authorization_server that concern the retrieval of tokens through refresh tokens.
//

func (this *AuthorizationServer) refreshToken() {
	if this.token.accessToken != "" && this.config.RefreshTokenStructure != "" {
		token, err := this.retrieveRefreshTokenFromServer()

		if err != nil { // Refresh Token failed, try new Token
			logp.Warn(err.Error())
			this.getTokenAndHandleStatus()

		} else {
			this.status = Ok
			this.token.accessToken = token.accessToken
			this.token.refreshToken = token.refreshToken
		}
	} else {
		this.getTokenAndHandleStatus()
	}
}

func (this *AuthorizationServer) getTokenAndHandleStatus() {
	token, status, err := this.retrieveTokenFromServer()
	this.status = status

	if status == Ok {
		this.token = *token
	} else if status == Error {
		logp.Warn(fmt.Sprintf("Could not retrieve a token at this moment; Error:  %v", err))
	} else {
		logp.Warn("Unable to retrieve a token, Invalid Config and/or Authorization")
	}
}

// Handles the response from the Authorization-Server and parses the data
func (this *AuthorizationServer) retrieveRefreshTokenFromServer() (*authorizationToken, error) {
	response, err := this.connector.retrieveTokenWithRefreshToken(this.config.AuthString, this.token.refreshToken, this.config.Url)

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

	access_token, refresh_token, access_duration := this.extractResponseBody(*data)

	return newAuthorizationToken(access_token, refresh_token, access_duration), nil

}
