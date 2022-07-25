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

func (this connectorTest) retrieveToken(authString string, authBody interface{}, url string) (*http.Response, error, string) {
	return this.response, this.err, this.status
}

func (this connectorTest) retrieveTokenWithRefreshToken(refreshToken string, url string) (*http.Response, error) {
	if this.responseRefresh == nil && this.errRefresh == nil {
		return this.response, this.err
	}

	return this.responseRefresh, this.errRefresh
}
