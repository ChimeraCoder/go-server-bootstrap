package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
	"io/ioutil"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"log"
	"net/http"
	"net/url"
	"text/template"
)

const BCRYPT_COST = 12
const MIN_PASSWORD_LENGTH = 8
const PROFILE_SESSION = "profile"

var (
	httpAddr        = flag.String("addr", ":8000", "HTTP server address")
	baseTmpl string = "templates/base.tmpl"
	store           = sessions.NewCookieStore([]byte(COOKIE_SECRET)) //CookieStore uses secure cookies
	decoder         = schema.NewDecoder()                            //From github.com/gorilla/schema

	//The following three variables can be defined using environment variables
	//to avoid committing them by mistake
	//Alternatively, place variable declarations in a separate conf.go file
	//which is already in the .gitignore file

	//COOKIE_SECRET = []byte(os.Getenv("COOKIE_SECRET"))
	//APP_ID = os.Getenv("APP_ID")
	//APP_SECRET = os.Getenv("APP_SECRET")
)

func serveProfile(w http.ResponseWriter, r *http.Request, c *Credentials) {
	fmt.Fprint(w, "This is where the user's profile information goes!")
	return
}

func serveCallback(w http.ResponseWriter, r *http.Request) {
	switch {
	//TODO use oauth library to simplify the following
	//Only serve GET requests
	case r.Method == "GET":
		{
			log.Print("Clef login")
			vals, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				panic(err)
			}
			code := vals.Get("code")
			v := url.Values{}
			v.Set("code", code)
			v.Set("app_id", APP_ID)
			v.Set("app_secret", APP_SECRET)
			response, err := http.PostForm("https://clef.io/api/authorize", v)

			if err != nil {
				panic(err)
			} else {
				bts, err := ioutil.ReadAll(response.Body)
				if err != nil {
					panic(err)
				}
				result := make(map[string]interface{})
				json.Unmarshal(bts, &result)
				log.Print(result)
				access_token, ok := result["access_token"].(string)
				if !ok {
					log.Print("Something funky happened here: %v", result)
				}

				v := url.Values{}
				v.Set("access_token", access_token)
				response, err := http.PostForm("https://clef.io/api/info", v)
				if err != nil {
					panic(err)
				}
				bts, err = ioutil.ReadAll(response.Body)
				if err != nil {
					panic(err)
				}
				err = json.Unmarshal(bts, &result)
				log.Printf("Result: %v", result)

				session, _ := store.Get(r, PROFILE_SESSION)
				//session.Values["userid"] = access_token
				session.Values["access_token"] = access_token
				session.Save(r, w)

				//http.StatusFound is just an integer, so you can specify 302 directly
				http.Redirect(w, r, "/profile", http.StatusFound)
			}
		}
	//Return an error for all other HTTP methods
	default:
		{
			http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		}
	}
}

func serveLogin(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		{
			s1, _ := template.ParseFiles("templates/base.tmpl", "templates/login.tmpl")
			s1.ExecuteTemplate(w, "base", nil)
		}
	case "POST":
		{
			_ = r.ParseForm()
			values := r.Form
			user := new(User)
			decoder.Decode(user, values)
			email := user.Email
			password := user.Password
			full_user, err := comparePassword(email, password)
			if err != nil {
				log.Printf("Error fetching user: %v", err)
				s1, _ := template.ParseFiles("templates/base.tmpl", "templates/login.tmpl")
				s1.ExecuteTemplate(w, "base", "Error fetching user")
				return
			}

			session, _ := store.Get(r, PROFILE_SESSION)
			session.Values["userid"] = full_user.Email
			session.Save(r, w)
			http.Redirect(w, r, "/profile", http.StatusFound)
		}

	}
}

//Fetch the user from the database and check if the passwords match
//If the passwords do not match, return a nil pointer, not a user struct
func comparePassword(email string, candidate_password string) (user *User, err error) {
	user = new(User)
	err = withCollection("users", func(c *mgo.Collection) error {
		return c.Find(bson.M{"email": email}).One(user)
	})
	if err != nil {
		user = nil
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(candidate_password))
	if err != nil {
		user = nil
	}
	return
}

func serveRegister(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		{
			s1, _ := template.ParseFiles("templates/base.tmpl", "templates/register.tmpl")
			s1.ExecuteTemplate(w, "base", nil)
		}

	case "POST":
		{
			//Create a User struct, though it will still need to be validated
			_ = r.ParseForm()
			values := r.Form
			user := new(User)
			decoder.Decode(user, values)

			//Password validation
			if len(r.FormValue("Password")) < MIN_PASSWORD_LENGTH || r.FormValue("Password") != r.FormValue("Password-confirm") {
				//TODO redirect with error message
				http.Redirect(w, r, "/register", http.StatusBadRequest)
				return
			}

			//Bcrypt password - never store passwords in plain text!
			password_hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password), BCRYPT_COST)
			if err != nil {
				panic(err)
			}
			user.Password = string(password_hashed)

			//Store user in database - in this case, mongodb
			//Swap out for your database of choice as needed
			if err := withCollection("users", func(c *mgo.Collection) error {
				return c.Insert(&user)
			}); err != nil {
				//Return an error if the database query failed
				http.Error(w, "Internal error", http.StatusInternalServerError)
			}
		}

	default:
		{
			http.Error(w, "Method not supported", http.StatusMethodNotAllowed)
		}
	}
}

func serveHome(w http.ResponseWriter, r *http.Request) {
	//You may want to refactor this, but this is how template inheritance works in Go
	s1, _ := template.ParseFiles("templates/base.tmpl", "templates/index.tmpl")
	s1.ExecuteTemplate(w, "base", map[string]string{"APP_ID": APP_ID})
}

func main() {
	var err error

	//Initialize mongodb connection, assuming mongo.go is present
	//If you are using another database setup, swap out this section
	mongodb_session, err = mgo.Dial(MONGODB_URL)
	if err != nil {
		panic(err)
	}
	mongodb_session.SetMode(mgo.Monotonic, true)
	mongodb_session.EnsureSafe(&mgo.Safe{1, "", 0, true, false})
	defer mongodb_session.Close()

	r := mux.NewRouter()

	r.HandleFunc("/", serveHome)
	r.HandleFunc("/callback", serveCallback)
	r.HandleFunc("/register", serveRegister)
	r.HandleFunc("/login", serveLogin)
	r.Handle("/profile", &authHandler{serveProfile, false})
	r.Handle("/static/", http.FileServer(http.Dir("public")))
	http.Handle("/", r)

	if err := http.ListenAndServe(*httpAddr, nil); err != nil {
		log.Fatalf("Error listening, %v", err)
	}
}
