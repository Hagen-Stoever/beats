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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetAuthorizationHeader(t *testing.T) {
	auth := OAuth{Url: "notAUrl", AuthString: "someString", TokenType: "Bearer"}
	uut := AuthorizationServer{config: auth, token: authorizationToken{accessToken: "aToken"}}

	result := uut.GetAuthorizationHeader()

	assert.Equal(t, "Bearer aToken", result)
}

// IsActive

func TestIsActive_Ok(t *testing.T) {
	uut := AuthorizationServer{status: Ok}

	result := uut.IsActive()

	assert.True(t, result)
}

func TestIsActive_Error(t *testing.T) {
	uut := AuthorizationServer{status: Error}

	result := uut.IsActive()

	assert.True(t, result)
}

func TestIsActive_Unauthorized(t *testing.T) {
	uut := AuthorizationServer{status: Unauthorized}

	result := uut.IsActive()

	assert.False(t, result)
}

func TestIsActive_Undefined(t *testing.T) {
	uut := AuthorizationServer{status: Undefined}

	result := uut.IsActive()

	assert.False(t, result)
}

// updateTokenPeriodically

func TestUpdateTokenPeriodically_wait15Seconds(t *testing.T) {
	// given
	auth := OAuth{TokenExpireTime: 15, RetryTime: 20}
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, status: Undefined}
	uut := AuthorizationServer{config: auth, connector: connector, status: Ok}

	// when
	startTime := time.Now()
	uut.updateTokenPeriodically()
	endTime := time.Now()

	// then
	duration := endTime.Sub(startTime)
	assert.True(t, 14 < duration.Seconds() && duration.Seconds() < 16)
}

func TestUpdateTokenPeriodically_wait20Seconds(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, status: Undefined}
	auth := OAuth{TokenExpireTime: 15, RetryTime: 20}
	uut := AuthorizationServer{config: auth, connector: connector, status: Error}

	startTime := time.Now()
	uut.updateTokenPeriodically()
	endTime := time.Now()

	duration := endTime.Sub(startTime)
	assert.True(t, 19 < duration.Seconds() && duration.Seconds() < 21)
}

func TestUpdateTokenPeriodically_wait10Seconds(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, status: Undefined}
	auth := OAuth{TokenExpireTime: 1, RetryTime: 2}
	uut := AuthorizationServer{config: auth, connector: connector, status: Ok}

	startTime := time.Now()
	uut.updateTokenPeriodically()
	endTime := time.Now()

	duration := endTime.Sub(startTime)
	assert.True(t, 9 < duration.Seconds() && duration.Seconds() < 11)
}

func TestUpdateTokenPeriodically_cancelOnUndefined(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, status: Undefined}
	auth := OAuth{TokenExpireTime: 15, RetryTime: 20}
	uut := AuthorizationServer{config: auth, connector: connector, status: Undefined}

	startTime := time.Now()
	uut.updateTokenPeriodically()
	endTime := time.Now()

	duration := endTime.Sub(startTime)
	assert.True(t, duration.Seconds() < 1)
}

//
// retrieveTokenFromServer
//

func TestRetrieveTokenFromServer_ok(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseOk, status: Ok}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, status, err := uut.retrieveTokenFromServer()

	assert.Equal(t, Ok, status)
	assert.Equal(t, nil, err)
	assert.Equal(t, "tokenValue", token.accessToken)
	assert.Equal(t, "refreshTokenValue", token.refreshToken)
	assert.Equal(t, 15, token.expiresIn)
}

func TestRetrieveTokenFromServer_errorWhileRetrieving(t *testing.T) {
	err := errors.New("Some Error")
	var connector authorizationServerConnector = connectorTest{response: responseOk, err: err, status: Undefined}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, status, err := uut.retrieveTokenFromServer()

	assert.Equal(t, Error, status)
	assert.Equal(t, err, err)
	assert.Nil(t, token)
}

func TestRetrieveTokenFromServer_unauthorizedBeforeCall(t *testing.T) {
	err := errors.New("Some Error")
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, err: err, status: Unauthorized}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, status, err := uut.retrieveTokenFromServer()

	assert.Equal(t, Unauthorized, status)
	assert.Equal(t, err, err)
	assert.Nil(t, token)
}

func TestRetrieveTokenFromServer_unauthorizedAfterCall(t *testing.T) {
	err := errors.New("Some Error")
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, err: nil, status: Unauthorized}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, status, err := uut.retrieveTokenFromServer()

	assert.Equal(t, Unauthorized, status)
	assert.Equal(t, err, err)
	assert.Nil(t, token)
}

func TestRetrieveTokenFromServer_unableToParse(t *testing.T) {
	err := errors.New("Some Error")
	var connector authorizationServerConnector = connectorTest{response: responseNotJson, err: nil, status: Ok}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, status, err := uut.retrieveTokenFromServer()

	assert.Equal(t, Error, status)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Unable to parse the Response from the Authorization-Server. Response must be a JSON.")
	assert.Nil(t, token)
}

// refreshToken

func TestRefreshToken_refreshWithRefreshToken(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseOk, err: nil, status: Ok}
	auth := OAuth{RefreshTokenStructure: "grant=refresh&refreshToken=%s"}
	uut := AuthorizationServer{config: auth, connector: connector, token: authorizationToken{refreshToken: "someString"}}

	uut.refreshToken()

	assert.Equal(t, Ok, uut.status)
	assert.Equal(t, "tokenValue", uut.token.accessToken)
}

func TestRefreshToken_refreshWithAuthBody(t *testing.T) {
	type tempBody struct {
		value string
	}
	body := tempBody{value: "someTempValue"}
	var connector authorizationServerConnector = connectorTest{response: responseOk, err: nil, status: Ok}
	auth := OAuth{AuthBody: body}
	uut := AuthorizationServer{config: auth, connector: connector}

	uut.refreshToken()

	assert.Equal(t, Ok, uut.status)
	assert.Equal(t, "tokenValue", uut.token.accessToken)
}

func TestRefreshToken_refreshWithAuthString(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseOk, err: nil, status: Ok}
	auth := OAuth{AuthString: "someAuthString"}
	uut := AuthorizationServer{config: auth, connector: connector}

	uut.refreshToken()

	assert.Equal(t, Ok, uut.status)
	assert.Equal(t, "tokenValue", uut.token.accessToken)
}

func TestRefreshToken_retryOnError(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, err: nil, status: Ok, responseRefresh: responseOk, errRefresh: nil}
	auth := OAuth{RefreshTokenStructure: "grant=refresh&refreshToken=%s"}
	uut := AuthorizationServer{config: auth, connector: connector, token: authorizationToken{refreshToken: "someString"}}

	uut.refreshToken()

	assert.Equal(t, Ok, uut.status)
	assert.Equal(t, "tokenValue", uut.token.accessToken)
}

// getTokenAndHandleStatus

func TestGetTokenAndHandleStatus(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseOk, err: nil, status: Ok}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	uut.getTokenAndHandleStatus()

	assert.Equal(t, Ok, uut.status)
	assert.NotNil(t, uut.token)
}

func TestGetTokenAndHandleStatus_Unauthorized(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, err: nil, status: Ok}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	uut.getTokenAndHandleStatus()

	assert.Equal(t, Unauthorized, uut.status)
	assert.NotNil(t, uut.token)
}

// retrieveRefreshTokenFromServer

func TestRetrieveRefreshTokenFromServer_Ok(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseOk, err: nil, status: Ok}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, err := uut.retrieveRefreshTokenFromServer()

	assert.NotNil(t, token)
	assert.Nil(t, err)
	assert.Equal(t, "tokenValue", token.accessToken)
}

func TestRetrieveRefreshTokenFromServer_error(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, err: errors.New("Some Errors"), status: Ok}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, err := uut.retrieveRefreshTokenFromServer()

	assert.Nil(t, token)
	assert.NotNil(t, err)
	assert.Equal(t, "Some Errors", err.Error())
}

func TestRetrieveRefreshTokenFromServer_unauthorized(t *testing.T) {
	var connector authorizationServerConnector = connectorTest{response: responseUnauthorized, err: nil, status: Ok}
	auth := OAuth{}
	uut := AuthorizationServer{config: auth, connector: connector}

	token, err := uut.retrieveRefreshTokenFromServer()

	assert.Nil(t, token)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "Authorization-Server responded with "))
	assert.True(t, strings.Contains(err.Error(), " when trying to use refresh-token"))
}

// parseResponseBodyToMap

func TestParseResponseBodyToMap_ok(t *testing.T) {
	data, err := parseResponseBodyToMap(responseBodyOk)

	assert.Nil(t, err)
	assert.NotNil(t, (*data)["access_token"])
	assert.NotNil(t, (*data)["refresh_token"])
	assert.NotNil(t, (*data)["expires_in"])
}

func TestParseResponseBodyToMap_okWithMissingFields(t *testing.T) {
	data, err := parseResponseBodyToMap(responseBodyMissingFields)

	assert.Nil(t, err)
	assert.NotNil(t, (*data)["access_token"])
	assert.Nil(t, (*data)["refresh_token"])
	assert.Nil(t, (*data)["expires_in"])
}

func TestParseResponseBodyToMap_errorNotJson(t *testing.T) {
	data, err := parseResponseBodyToMap(responseBodyNotJson)

	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Unable to parse the Response from the Authorization-Server. Response must be a JSON.")
	assert.Nil(t, data)
}

func TestParseResponseBodyToMap_responseIsEmpty(t *testing.T) {
	data, err := parseResponseBodyToMap(responseBodyEmpty)

	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Unable to parse the Response from the Authorization-Server. Response must be a JSON.")
	assert.Nil(t, data)
}

// extractResponseBody

func TestExtractResponseBody(t *testing.T) {
	token, refresh, expires := extractResponseBody(responseMapOk)

	assert.Equal(t, "tokenValue", token)
	assert.Equal(t, "refreshTokenValue", refresh)
	assert.Equal(t, 15, expires)
}

func TestExtractResponseBody_missingFields(t *testing.T) {
	token, refresh, expires := extractResponseBody(responseMapMissingFields)

	assert.Equal(t, "tokenValue", token)
	assert.Equal(t, "", refresh)
	assert.Equal(t, 0, expires)
}

// maxOf

func TestMaxOf(t *testing.T) {
	result := maxOf(324, 23, 42, 342, 34, 324, 234, 4, 44, 23, 42, 0, 0, 34, 4324, -4, -2342342)

	assert.Equal(t, 4324, result)
}

func TestMaxOf_onlyOneElement(t *testing.T) {
	result := maxOf(324)

	assert.Equal(t, 324, result)
}
