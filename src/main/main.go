package main

import (
	"context"
	"encoding/gob"
	"html/template"
	"log"
	"net/http"

	GH "github.com/google/go-github/github"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var store = sessions.NewCookieStore([]byte("secret"))

type User struct {
	Name   string
	Email  string
	Avatar string
}

var OAuthConf *oauth2.Config

func init() {
	OAuthConf = &oauth2.Config{
		ClientID:     "{{oauth client id}}",
		ClientSecret: "{{oauth client secret}}",
		RedirectURL:  "{{callback url}}",
		Scopes:       []string{"user"},
		Endpoint:     github.Endpoint,
	}
}

func main() {
	gob.Register(User{})

	http.HandleFunc("/", MainHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/auth/callback", CallbackHandler)

	log.Fatal(http.ListenAndServe(":8000", nil))
}

func RenderHtmlTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, _ := template.ParseFiles(name)
	tmpl.Execute(w, data)
}

func MainHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userInfo := session.Values["user"]
	if userInfo == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
	} else {
		RenderHtmlTemplate(w, "main.html", userInfo)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Options = &sessions.Options{
		Path:   "/auth",
		MaxAge: 300,
	}

	state := uuid.New().String()
	session.Values["state"] = state
	session.Save(r, w)

	RenderHtmlTemplate(w, "login.html", OAuthConf.AuthCodeURL(state))
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	state := session.Values["state"]

	delete(session.Values, "state")
	session.Save(r, w)

	if state != r.FormValue("state") {
		http.Error(w, "Invalid session state", http.StatusUnauthorized)
		return
	}

	token, err := OAuthConf.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	client := OAuthConf.Client(context.Background(), token)
	ghClient := GH.NewClient(client)
	user, _, err := ghClient.Users.Get(context.Background(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	authUser := User{
		Name:   user.GetLogin(),
		Email:  user.GetEmail(),
		Avatar: user.GetAvatarURL(),
	}

	session.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400,
	}
	session.Values["user"] = authUser
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}
