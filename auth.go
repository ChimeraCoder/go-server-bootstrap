package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/dchest/authcookie"
	"log"
	"net/http"
	"strings"
	"time"
)

type Credentials struct {
	UserId string
	//etc.
}

// authHandler reads the auth cookie and invokes a handler with the result.
type authHandler struct {
	handler  func(w http.ResponseWriter, r *http.Request, c *Credentials)
	optional bool //Is authentication required for this request? Defaults to optional = false (ie, it is required)
}

// addCookie adds a cookie to the response. The cookie value is the base64
// encoding of the json encoding of data. If data is nil, then the cookie is
// deleted. 
//For illustration these two functions have been adapted from the library "github.com/garyburd/go-oauth/oauth"
func addCookie(w http.ResponseWriter, name string, data interface{}, maxAge time.Duration) error {
	c := http.Cookie{
		Name:     name,
		Path:     "/",
		HttpOnly: true,
	}
	if data == nil {
		maxAge = -10000 * time.Second
	} else {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(data); err != nil {
			return err
		}
		c.Value = base64.URLEncoding.EncodeToString(b.Bytes())
	}
	if maxAge != 0 {
		c.MaxAge = int(maxAge / time.Second)
		c.Expires = time.Now().Add(maxAge)
	}
	http.SetCookie(w, &c)
	return nil
}

// getCookie gets a base64 and json encoded value from a cookie.  
func getCookie(r *http.Request, name string, value interface{}) error {
	c, err := r.Cookie(name)
	if err != nil {
		return err
	}
	return json.NewDecoder(base64.NewDecoder(base64.URLEncoding, strings.NewReader(c.Value))).Decode(value)
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//Check if they are already logged in
	var cookie string

	err := getCookie(r, "auth", &cookie)
	if err == nil {
		//Found a cookie

		login := authcookie.Login(cookie, COOKIE_SECRET)
		if login != "" {
			//access for login granted
			log.Print("Access granted! Redirecting...")

			h.handler(w, r, &Credentials{login})
			return

		} else {
			//access denied
			log.Print("Access denied")
		}
	} else {
		log.Printf("Error getting cookie: %v", err)

	}
	//The cookie could not be retrieved OR was invalid
	log.Print("Could not retrieve valid cookie")

	http.Redirect(w, r, "/", 302)
}
