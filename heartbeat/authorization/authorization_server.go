package authorization

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
)

// A structure that manages the connection to an Authorization-Server and keeps the access-Token valid.
type AuthorizationServer struct {
	Type      string
	token     authorizationToken
	status    string
	connector authorizationServerConnector
	config    OAuth
}

const (
	Ok           string = "2XX" // A Token can be retrieved
	Unauthorized        = "4XX" // A Token can not be retrieved, because something was incorrectly configured
	Error               = "5XX" // A Token could not be retrieved, because the server has an error, try to retry later
	Undefined           = "XXX"
)

// this Object does not validate the given parameter
func newAuthorizationServer(auth *OAuth, connector *authorizationServerConnector) *AuthorizationServer {
	server := new(AuthorizationServer)

	server.status = Ok
	server.connector = *connector
	server.config = *auth

	server.getTokenAndHandleStatus()

	go server.updateTokenPeriodically()

	return server
}

// retuns the value of an Authorization-Header, i.e. tokenType and token
func (this *AuthorizationServer) GetAuthorizationHeader() string {
	return this.config.TokenType + " " + this.token.accessToken

}

// Returns true if this instance can theoretically obtain an Token from the Authorization Server
// but that does not mean that an access Token will be valid at a given moment.
// If an Authorization-Server returned 500, this will still be active.
func (this *AuthorizationServer) IsActive() bool {
	return this.status == Ok || this.status == Error
}

// Used to refresh the Token once it expires but also retries to retrieve an Token if the server responded with 500.
// If a token can not be retrieved due to invalid credentials, than this will stop to loop.
func (this *AuthorizationServer) updateTokenPeriodically() {
	const minSleepTime int = 10
	const expirationBuffer int = 10 //if a token expires in 90 seconds, then after 90 -10 = 80 seconds a new request will be started.

	for true { // do this for all eternity
		var sleepDuration int

		switch this.status {
		case Ok:
			sleepDuration = maxOf(this.token.expiresIn-expirationBuffer, minSleepTime, this.config.TokenExpireTime)
		case Error:
			sleepDuration = maxOf(this.config.RetryTime, minSleepTime)
		default:
			return
		}

		time.Sleep(time.Duration(sleepDuration) * time.Second)

		if this.status == Ok {
			this.refreshToken()
		} else {
			this.getTokenAndHandleStatus()
		}
	}

}

//
//---- Access Token -------- Access Token -------- Access Token -------- Access Token ----
//

// Handles the response from the Authorization-Server and parses the data
func (this *AuthorizationServer) retrieveTokenFromServer() (*authorizationToken, string, error) {
	response, err, status := this.connector.retrieveToken(this.config.AuthString, this.config.AuthBody, this.config.Url)

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
		access_duration = this.config.TokenExpireTime
	}

	return newAuthorizationToken(access_token, refresh_token, access_duration), Ok, nil

}

//
//---- Refreshing Token -------- Refreshing Token -------- Refreshing Token -------- Refreshing Token -------- Refreshing Token ----
//

// Uses the refresh token or the authorization-credentials to retrieve a new token
// and then it saves the token and the status
func (this *AuthorizationServer) refreshToken() {
	if this.token.refreshToken != "" && this.config.RefreshTokenStructure != "" {
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
	body := fmt.Sprintf(this.config.AuthString, this.token.refreshToken)
	response, err := this.connector.retrieveTokenWithRefreshToken(body, this.config.Url)

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

func maxOf(vars ...int) int {
	max := vars[0]

	for _, i := range vars {
		if max < i {
			max = i
		}
	}

	return max
}
