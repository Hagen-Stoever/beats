package authorization

import "time"

type AuthorizationServer struct {
	Type      string
	token     authorizationToken
	status    string
	connector connector
	config    OAuth
}

const (
	Ok           string = "2XX" // A Token can be retrieved
	Unauthorized        = "4XX" // A Token can not be retrieved, because something was incorrectly configured
	Error               = "5XX" // A Token could not be retrieved, because the server has an error, try to retry later
	Undefined           = "XXX"
	Stopped             = "Stp"
)

// this Object does not validate the given parameter
func newAuthorizationServer(auth *OAuth, connector *connector) *AuthorizationServer {
	server := new(AuthorizationServer)

	server.status = Ok
	server.connector = *connector
	server.config = *auth

	server.getTokenAndHandleStatus()

	go server.updateTokenPeriodically()

	return server
}

func (this *AuthorizationServer) GetAuthorizationHeader() string {
	return this.config.TokenType + " " + this.token.accessToken

}

func (this *AuthorizationServer) updateTokenPeriodically() {
	const minimumSleepTime int = 10
	const expirationBuffer int = 10

	for true { // do this for all eternity
		var sleepDuration int

		switch this.status {
		case Ok:
			sleepDuration = maxOf(this.token.expiresIn-expirationBuffer, minimumSleepTime, this.config.TokenExpireTime)
		case Error:
			sleepDuration = this.config.RetryTime
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

// Returns true if this instance can theoretically obtain an Token from the Authorization Server
// but that does not mean that an access Token will be valid at a given moment.
// If an Authorization-Server returned 500, this will still be active.
func (this *AuthorizationServer) IsActive() bool {
	return this.status == Ok || this.status == Error
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
