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
	"io"
	"net/http"
	"strings"
)

var tokenResponse = `{
	"access_token": "tokenValue",
	"expires_in": 15,
	"refresh_token": "refreshTokenValue",
	"token_type": "Bearer",
	"scope": ""
}`
var tokenResponseMissingFields = `{
	"access_token": "tokenValue",
	"token_type": "Bearer"
}`
var tokenResponseError = `{
	"error": "unauthorized_client"
	"error_description": "invalid client secret"
}`
var tokenResponseNotJson = "some info not as json"

var responseBodyOk = io.NopCloser(strings.NewReader(tokenResponse))
var responseBodyMissingFields = io.NopCloser(strings.NewReader(tokenResponseMissingFields))
var responseBodyUnauthorized = io.NopCloser(strings.NewReader(tokenResponseError))
var responseBodyNotJson = io.NopCloser(strings.NewReader(tokenResponseNotJson))
var responseBodyEmpty = io.NopCloser(strings.NewReader(""))

var responseOk = &http.Response{Status: "200 OK", StatusCode: 200, Body: responseBodyOk}
var responseNotJson = &http.Response{Status: "200 OK", StatusCode: 200, Body: responseBodyNotJson}
var responseUnauthorized = &http.Response{Status: "401 Unauthorized", StatusCode: 401, Body: responseBodyUnauthorized}

var responseMapOk = map[string]interface{}{
	"access_token":  "tokenValue",
	"refresh_token": "refreshTokenValue",
	"expires_in":    float64(15),
}

var responseMapMissingFields = map[string]interface{}{
	"access_token": "tokenValue",
}

type connectorTest struct {
	response        *http.Response
	err             error
	status          string
	responseRefresh *http.Response
	errRefresh      error
}

func (this connectorTest) retrieveToken(authString string, authBody interface{}, url string, certPath string) (*http.Response, error, string) {
	return this.response, this.err, this.status
}

func (this connectorTest) retrieveTokenWithRefreshToken(refreshToken string, url string, certPath string) (*http.Response, error) {
	if this.responseRefresh == nil && this.errRefresh == nil {
		return this.response, this.err
	}

	return this.responseRefresh, this.errRefresh
}
