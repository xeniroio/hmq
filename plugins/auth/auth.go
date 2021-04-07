package auth

import (
	authfile "github.com/fhmq/hmq/plugins/auth/authfile"
	"github.com/fhmq/hmq/plugins/auth/authhttp"
	"github.com/fhmq/hmq/plugins/auth/authjwt"
)

const (
	AuthHTTP = "authhttp"
	AuthFile = "authfile"
	AuthJwt  = "authjwt"
)

type Auth interface {
	CheckACL(action, clientID, username, ip, topic string) bool
	CheckConnect(clientID, username, password string) bool
}

func NewAuth(name string) Auth {
	switch name {
	case AuthHTTP:
		return authhttp.Init()
	case AuthFile:
		return authfile.Init()
	case AuthJwt:
		return authjwt.Init()
	default:
		return &mockAuth{}
	}
}
