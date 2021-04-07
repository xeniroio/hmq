package authjwt

import (
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"time"

	"github.com/fhmq/hmq/logger"
	"go.uber.org/zap"
)

var log = logger.Get().Named("authhttp")

type authJWT struct {
	authURL string
	client  *http.Client
}

func Init() *authJWT {
	c := &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost:     100,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: time.Second * 100,
	}
	a := &authJWT{
		authURL: "http://localhost/auth",
		client:  c,
	}
	return a
}

func (a *authJWT) CheckConnect(clientID, username, password string) bool {
	return true
}

func (a *authJWT) CheckACL(action, clientID, username, ip, topic string) bool {
	log.Info("CheckACL in authJWT")
	p := path.Join(a.authURL, "verify", topic, action)
	req, err := http.NewRequest("POST", p, nil)
	if err != nil {
		log.Error("new request super: ", zap.Error(err))
		return false
	}
	req.Header.Add("Authorization", username)

	resp, err := a.client.Do(req)
	if err != nil {
		log.Error("request super: ", zap.Error(err))
		return false
	}
	defer resp.Body.Close()

	io.Copy(ioutil.Discard, resp.Body)
	if resp.StatusCode == http.StatusOK {
		return true
	}
	return false
}
