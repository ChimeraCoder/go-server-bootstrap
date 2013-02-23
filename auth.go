package main

import (
	"log"
	"net/http"
)

type Credentials struct {
	UserId      string //Must be non-empty for ALL valid login (OAuth or password)
	AccessToken string //Will be non-empty only for OAuth-based login
	//etc.
}

// authHandler reads the auth cookie and invokes a handler with the result.
type authHandler struct {
	handler  func(w http.ResponseWriter, r *http.Request, c *Credentials)
	optional bool //Is authentication required for this request? Defaults to optional = false (ie, it is required)
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//Check if they are already logged in

	session, err := store.Get(r, PROFILE_SESSION)
	if err != nil {
		panic(err)
	}

	//If no value is found, this string assertion will fail
	userid, ok := session.Values["userid"].(string)
	if ok && userid != "" {
		//access for login granted

		//fetch the access token if it exists
		access_token, ok := session.Values["access_token"].(string)
		if !ok {
			access_token = ""
		}

		h.handler(w, r, &Credentials{userid, access_token})
		return
	} else {
		log.Print("Access denied")
		http.Redirect(w, r, "/", 302)
	}

}
