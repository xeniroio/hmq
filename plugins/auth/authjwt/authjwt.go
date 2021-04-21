package authjwt

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/fhmq/hmq/logger"
	"go.uber.org/zap"
)

var (
	log = logger.Get().Named("authhttp")
	uRe = regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
)

type authJWT struct {
	authURL *url.URL
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

	u, _ := url.Parse("http://localhost:8080/login/auth")
	a := &authJWT{
		authURL: u,
		client:  c,
	}
	a.getEnv()

	return a
}

func (a *authJWT) getEnv() {
	if h := os.Getenv("AUTH_HOST"); len(h) > 0 {
		if !uRe.MatchString(h) {
			log.Error("ip formate error: ", zap.String("AUTH_HOST", h))
			os.Exit(1)
		}
		a.authURL.Host = h
	}

	if p := os.Getenv("AUTH_PATH"); len(p) > 0 {
		a.authURL.Path = p
	}
}

func (a *authJWT) CheckConnect(clientID, username, password string) bool {
	return true
}

func (a *authJWT) CheckACL(action, clientID, username, ip, topic string) bool {
	req, err := http.NewRequest("POST", a.authURL.String()+topic+"/"+action, nil)
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
