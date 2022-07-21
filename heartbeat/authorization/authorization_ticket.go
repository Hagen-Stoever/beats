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

import "time"

// This structure saves the information of a token
type AuthorizationToken struct {
	accessToken          string
	refreshToken         string
	expiresIn            int
	accessTokenExpiresAt time.Time
}

// If the lifespan of a token is 0 or less, then the token effectivly will never expire
// The unit for the lifespan is second
func newAuthorizationToken(access_token string, refresh_token string, expiresIn int) *AuthorizationToken {
	newToken := new(AuthorizationToken)
	newToken.accessToken = access_token
	newToken.refreshToken = refresh_token
	newToken.expiresIn = expiresIn

	now := time.Now()
	if expiresIn > 0 {
		newToken.accessTokenExpiresAt = now.Add(time.Second * time.Duration(expiresIn))
	} else {
		newToken.accessTokenExpiresAt = time.Unix(1<<63-62135596801, 999999999) // maximum time value https://stackoverflow.com/a/32620397 by @cce
	}

	return newToken
}

func (this AuthorizationToken) isExpired() bool {
	return this.accessTokenExpiresAt.Before(time.Now())
}
