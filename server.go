package main

import (
    "net/http"
    "log"
    "text/template"
    "flag"
    "time"
    "strings"
    "bytes"
    "encoding/json"
    "encoding/base64"
    "os"
    "fmt"
    "net/url"
    "io/ioutil"
    "github.com/dchest/authcookie"
)


const BCRYPT_COST = 12

var (
    httpAddr = flag.String("addr", ":8000", "HTTP server address")
    baseTmpl string = "templates/base.tmpl"
    COOKIE_SECRET = []byte(os.Getenv("COOKIE_SECRET"))
    APP_ID = os.Getenv("APP_ID")
    APP_SECRET = os.Getenv("APP_SECRET")

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
func addCookie(w http.ResponseWriter, name string, data interface{}, maxAge time.Duration) error {    c := http.Cookie{
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


func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request){
            //Check if they are already logged in
            var cookie string

            err := getCookie(r, "auth", &cookie)
            if err == nil {
                //Found a cookie
                log.Print("Found cookie! %v", cookie)

                login := authcookie.Login(cookie, COOKIE_SECRET)
                if login != "" {
                    //access for login granted
                    log.Print("Access granted! Redirecting...")
                    log.Printf("Cookie was %s", login)

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

func serveProfile(w http.ResponseWriter, r *http.Request, c *Credentials){
    fmt.Fprint(w, "This is where the user's profile information goes!")
    return
}

func serveLogin(w http.ResponseWriter,  r *http.Request) {
    switch {
        //Only serve GET requests
        case r.Method == "GET": {
            vals, err := url.ParseQuery(r.URL.RawQuery)
            if err != nil {panic (err)}
            code := vals.Get("code")
            log.Printf("Received code %s", code)
            v := url.Values{}
            v.Set("code", code)
            v.Set("app_id", APP_ID)
            v.Set("app_secret", APP_SECRET)
            log.Printf("Sending %v", v)
            response, err := http.PostForm("https://clef.io/api/authorize", v)
            log.Printf("received : %v", response)
            log.Printf("received header %+v", response.Header)
            log.Printf("received access_token %v", response.Header.Get("access_token"))

            if err != nil {
                panic(err)
            } else{
                bits, err := ioutil.ReadAll(response.Body)
                if err != nil { panic(err)}
                log.Printf("Found %s", string(bits))
                result := make(map[string]interface{})
                json.Unmarshal(bits, &result)
                access_token, ok := result["access_token"].(string)
                if !ok {
                    log.Print("Something funky happened here %v", result)
                }

                v := url.Values{}
                v.Set("access_token", access_token)
                response, err  := http.PostForm("https://clef.io/api/info",v)
                if err != nil { panic(err)}
                log.Printf("received next %v", response)
                log.Printf("received body %v", response.Header.Get("body"))
                bits, err = ioutil.ReadAll(response.Body)
                if err != nil { panic(err)}
                log.Printf("Found %s", string(bits))
                err = json.Unmarshal(bits, &result)
                
                //Set a cookie that is valid for 24 hours
                cookie := authcookie.NewSinceNow(access_token, 24 * time.Hour, COOKIE_SECRET)
                addCookie(w, "auth", cookie, 24*time.Hour)



                //http.StatusFound is just an integer, so you can specify 302 directly
                http.Redirect(w, r, "/profile", http.StatusFound)
            }
        }
        //Return an error for all other HTTP methods
        default: {
            http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
        }
    }
}



func serveHome(w http.ResponseWriter, r *http.Request){
    //The "/" path will be matched by default, so we need to check for a 404 error
    //you can use mux or something similar to refactor this part
    if r.URL.Path != "/" {
        http.Error(w, "Not Found", http.StatusNotFound)
    } else {
        //You may want to refactor this, but this is how template inheritance works in Go
        s1, _ := template.ParseFiles("templates/base.tmpl", "templates/index.tmpl")
        s1.ExecuteTemplate(w, "base", nil)
    }
}


func main() {
    http.HandleFunc("/", serveHome)
    http.HandleFunc("/login", serveLogin)
    http.Handle("/profile", &authHandler{serveProfile, false})
    http.Handle("/static/", http.FileServer(http.Dir("public")))

    if err := http.ListenAndServe(*httpAddr, nil); err != nil {
        log.Fatalf("Error listening, %v", err)
    }
}
