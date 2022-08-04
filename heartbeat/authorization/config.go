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

// Scheduler defines the syntax of a heartbeat.yml OAuth block
type OAuth struct {
	Url                   string      `config:"server_url"`
	AuthBody              interface{} `config:"auth_body"`
	AuthString            string      `config:"auth_string"`
	RefreshTokenStructure string      `config:"refresh_token_structure"`
	TokenType             string      `config:"token_type"`
	RetryTime             int         `config:"retry_time_seconds"`
	TokenExpireTime       int         `config:"token_expires_in"`
	CertificatePath       string      `config:"certificate"`
}
