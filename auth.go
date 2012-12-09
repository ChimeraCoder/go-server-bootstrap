package main

import (
	"log"
	"net/http"
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

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//Check if they are already logged in

    session, err := store.Get(r, PROFILE_SESSION)
    if err != nil{
        panic(err)
    }

    //If no value is found, this string assertion will fail
    access_token, ok := session.Values["access_token"].(string)
    if ok && access_token != ""{
        //access for login granted
        log.Print("Access granted! Redirecting... ")

        h.handler(w, r, &Credentials{access_token})
        return
    } else{
        log.Print("Access denied")

        http.Redirect(w, r, "/", 302)
    }

}
