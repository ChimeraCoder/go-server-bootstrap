package main

import (
    "net/http"
    "log"
    "text/template"
    "flag"
    "time"
    "encoding/json"
    "fmt"
    "net/url"
    "io/ioutil"
    "github.com/dchest/authcookie"
)


const BCRYPT_COST = 12

var (
    httpAddr = flag.String("addr", ":8000", "HTTP server address")
    baseTmpl string = "templates/base.tmpl"

    //The following three variables can be defined using environment variables
    //to avoid committing them by mistake
    //Alternatively, place variable declarations in a separate conf.go file
    //which is already in the .gitignore file

    //COOKIE_SECRET = []byte(os.Getenv("COOKIE_SECRET"))
    //APP_ID = os.Getenv("APP_ID")
    //APP_SECRET = os.Getenv("APP_SECRET")

)

func serveProfile(w http.ResponseWriter, r *http.Request, c *Credentials){
    fmt.Fprint(w, "This is where the user's profile information goes!")
    return
}

func serveLogin(w http.ResponseWriter,  r *http.Request) {
    switch {
        //TODO use oauth library to simplify the following
        //Only serve GET requests
        case r.Method == "GET": {
            vals, err := url.ParseQuery(r.URL.RawQuery)
            if err != nil {panic (err)}
            code := vals.Get("code")
            v := url.Values{}
            v.Set("code", code)
            v.Set("app_id", APP_ID)
            v.Set("app_secret", APP_SECRET)
            response, err := http.PostForm("https://clef.io/api/authorize", v)

            if err != nil {
                panic(err)
            } else{
                bits, err := ioutil.ReadAll(response.Body)
                if err != nil { panic(err)}
                result := make(map[string]interface{})
                json.Unmarshal(bits, &result)
                access_token, ok := result["access_token"].(string)
                if !ok {
                    log.Print("Something funky happened here: %v", result)
                }

                v := url.Values{}
                v.Set("access_token", access_token)
                response, err  := http.PostForm("https://clef.io/api/info",v)
                if err != nil { panic(err)}
                bits, err = ioutil.ReadAll(response.Body)
                if err != nil { panic(err)}
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
