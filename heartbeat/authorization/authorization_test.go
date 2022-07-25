package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadAuthorization_InactiveInvalidURL(t *testing.T) {
	config := OAuth{Url: "notAUrl", AuthString: "someString"}

	result := LoadAuthorization(&config, nil)
	assert.Equal(t, false, result.IsActive())
	assert.Equal(t, "", *result.GetAccessToken())
}

func TestLoadAuthorization_InactiveNoAuthorization(t *testing.T) {
	config := OAuth{Url: "http://example.com"}

	result := LoadAuthorization(&config, nil)
	assert.Equal(t, false, result.IsActive())
	assert.Equal(t, "", *result.GetAccessToken())
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
