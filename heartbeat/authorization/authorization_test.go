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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadAuthorization_InactiveInvalidURL(t *testing.T) {
	config := OAuth{Url: "notAUrl", AuthString: "someString"}

	result := LoadAuthorization(&config, nil)
	assert.Equal(t, false, result.IsActive())
}

func TestLoadAuthorization_InactiveNoAuthorization(t *testing.T) {
	config := OAuth{Url: "http://example.com"}

	result := LoadAuthorization(&config, nil)
	assert.Equal(t, false, result.IsActive())
}

func TestCheckUrl_IpOk(t *testing.T) {
	url := "http://192.168.1.1/metrics"

	result := checkUrl(url)
	assert.Equal(t, Ok, result)
}

func TestCheckUrl_IpAndPort(t *testing.T) {
	url := "http://192.168.1.1:5000/metrics"

	result := checkUrl(url)
	assert.Equal(t, Ok, result)
}

func TestCheckUrl_Ok(t *testing.T) {
	url := "http://example.com"

	result := checkUrl(url)
	assert.Equal(t, Ok, result)
}

func TestCheckUrl_Error(t *testing.T) {
	url := "www.test.com"

	result := checkUrl(url)
	assert.Equal(t, Unauthorized, result)
}
