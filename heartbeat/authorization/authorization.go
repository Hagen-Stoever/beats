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
	"fmt"
	"net/url"

	"github.com/elastic/elastic-agent-libs/logp"
)

var activeAuthorization *Authorization

func GetActiveAuthorization() *Authorization {
	return activeAuthorization
}

const (
	Ok           string = "2XX" // A Token can be retrieved
	Unauthorized        = "4XX" // A Token can not be retrieved, because something was incorrectly configured
	Error               = "5XX" // A Token could not be retrieved, because the server has an error, try to retry later
	Undefined           = "XXX"
)

type Authorization struct {
	token     AuthorizationToken
	config    OAuth
	status    string
	TokenType string
}

func (this *Authorization) IsActive() bool {
	return this.status == Ok
}

func (this *Authorization) GetAccessToken() *string {
	return &this.token.accessToken
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

	urlStatus := checkUrl(newAuth)

	if urlStatus == Ok { // Get a Token from the Server
		handleToken(newAuth)
	} else {
		logp.Warn("Invalid Config, disabling OAuth-Feature")
		newAuth.status = Unauthorized
	}

	return newAuth
}

func checkUrl(auth *Authorization) string {
	url, err := url.Parse(auth.config.Url)

	if err != nil {
		fmt.Print()
		logp.Warn("Invalid URL for Authorization-Server; Error: " + err.Error())
		return Error
	} else if url.Host == "" {
		logp.Warn("Invalid URL for Authorization-Server; The host is missing - " + auth.config.Url)
		return Error
	} else if url.Scheme == "" {
		logp.Warn("No Scheme provided for Authorization-Server, using https as default")
		url.Scheme = "https"
		auth.config.Url = url.String()
	}

	return Ok
}
