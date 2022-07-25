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
	"net/url"

	"github.com/elastic/elastic-agent-libs/logp"
)

var activeAuthorization *Authorization

func GetAuthorizationServer() *authorizationServer {
	return activeAuthorization.server
}

type Authorization struct {
	config OAuth
	server *authorizationServer
}

func (this *Authorization) IsActive() bool {
	return this.server.status == Ok
}

func (this *Authorization) GetAccessToken() *string {
	return &this.server.token.accessToken
}

// Creates a new Instance of Authorization
func LoadAuthorization(config *OAuth) *Authorization {
	newAuth := new(Authorization)
	activeAuthorization = newAuth

	newAuth.config = *config

	// checking config for default values
	if newAuth.config.RetryTime == 0 {
		newAuth.config.RetryTime = 60
	}
	if newAuth.config.TokenType == "" {
		newAuth.config.TokenType = "Bearer"
	}
	// Default value for TokenExpireTime is 0

	status := checkConfig(config)
	if status == Ok {
		newAuth.server = newAuthorizationServer(config, &connector{}) // creates a new Object that retrieves automatically new Tokens.
	} else {
		newAuth.server = new(authorizationServer)
		newAuth.server.status = Unauthorized
		logp.Warn("Invalid Config, disabling OAuth-Feature")
	}

	return newAuth
}

func checkConfig(config *OAuth) string {
	if config.RefreshTokenStructure == "" {
		logp.Warn("No Structure for the Refresh-Token provided, ignoring refresh token")
	}

	if urlStatus := checkUrl(config.Url); urlStatus != Ok {
		return Unauthorized
	}

	if config.AuthString == "" && config.AuthBody == nil {
		return Unauthorized
	}

	return Ok
}

func checkUrl(providedUrl string) string {
	_, err := url.ParseRequestURI(providedUrl)

	if err != nil {
		logp.Warn("Invalid URL for Authorization-Server; Error: " + err.Error())
		return Unauthorized
	} else {
		return Ok
	}
}
