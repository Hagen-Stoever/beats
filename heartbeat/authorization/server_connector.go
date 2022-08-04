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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/elastic/elastic-agent-libs/logp"
)

// An interface that can be mocked
type authorizationServerConnector interface {
	retrieveToken(authString string, authBody interface{}, url string, certPath string) (*http.Response, error, string)
	retrieveTokenWithRefreshToken(refreshTokenBody string, url string, certPath string) (*http.Response, error)
}

// Contains all the functions that send HTTP-Requests.
type connector struct{}

// authString: a string containing the grantType and the credentials needed to retrieve a token
// authBody: An Object containing the credentials needed to retrieve a Token
// url: the Url of an Authorization-Server
func (this connector) retrieveToken(authString string, authBody interface{}, url string, certPath string) (*http.Response, error, string) {
	var request *http.Request
	var err error

	if authString != "" { // String
		request, _ = http.NewRequest("POST", url, bytes.NewBuffer([]byte(authString)))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else if authBody != nil { // JSON
		payloadBuf := new(bytes.Buffer)
		json.NewEncoder(payloadBuf).Encode(authBody)
		request, _ = http.NewRequest("POST", url, payloadBuf)
		request.Header.Set("Content-Type", "application/json")
	} else {
		return nil, errors.New("No Authorization-Body defined."), Unauthorized
	}

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to send a request to %s ", url)), Unauthorized
	} else {
		logp.Info("Requesting a new Token.")
		cert := loadCertificate(certPath)
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: cert,
				},
			},
		}
		response, err := client.Do(request)
		return response, err, Undefined
	}
}

// refreshTokenStructure: A string that represents a the body of a request, must have a placeholder in it to insert the refreshToken.
// refreshToken: a string that is conform with rfc6749 https://datatracker.ietf.org/doc/html/rfc6749
// url: the Url of an Authorization-Server
func (this connector) retrieveTokenWithRefreshToken(refreshTokenBody string, url string, certPath string) (*http.Response, error) {
	cert := loadCertificate(certPath)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: cert,
			},
		},
	}

	if req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(refreshTokenBody))); err == nil {
		logp.Info("Requesting a new Token with a refresh Token")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		return client.Do(req)
	} else {
		return nil, errors.New("Unable to parse the refresh token")
	}
}

func loadCertificate(certPath string) *x509.CertPool {
	caCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		logp.Warn("Unable to load the certificate file while requesting a token", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return caCertPool
}
