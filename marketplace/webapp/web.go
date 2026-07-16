// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webapp

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	"github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/marketplace/storage"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"github.com/scionproto/scion/pkg/log"
)

var templates = template.Must(template.ParseGlob("marketplace/templates/*.html"))

func Init(signer *registration.Signer, store *storage.MarketplaceStorage, mux *http.ServeMux, disableUserRegistration bool) {
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	sessionStore := sessions.NewCookieStore(sessionKey)
	sessionStore.Options = &sessions.Options{
		Secure:   true,
		HttpOnly: true,
		MaxAge:   0,
	}
	gob.Register(User{})
	gob.Register(addr.IA(0))
	h := &Handler{
		sessions:                sessionStore,
		signer:                  signer,
		store:                   store,
		disableUserRegistration: disableUserRegistration,
	}
	mux.HandleFunc("/", h.tokenHandler)
	mux.HandleFunc("/token", h.tokenHandler)
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/register", h.registerHandler)
	mux.HandleFunc("/balance", h.balanceHandler)
	mux.HandleFunc("/logout", h.logoutHandler)
	mux.HandleFunc("/aslogin", h.asLoginHandler)
	mux.HandleFunc("/asbalance", h.asBalanceHandler)
	mux.HandleFunc("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./marketplace/static/style.css")
	})
}

type Handler struct {
	sessions                sessions.Store
	store                   *storage.MarketplaceStorage
	signer                  *registration.Signer
	disableUserRegistration bool
}
type User struct {
	ID   int64
	Name string
}

func (h *Handler) SetSessionUser(w http.ResponseWriter, r *http.Request, user any) error {
	session, _ := h.sessions.Get(r, "session_id")
	session.Values["user"] = user
	session.Values["iat"] = time.Now().Unix()
	return session.Save(r, w)
}

func (h *Handler) GetSession(r *http.Request) (*sessions.Session, error) {
	session, err := h.sessions.Get(r, "session_id")
	if err != nil {
		return nil, err
	}
	iat, ok := session.Values["iat"].(int64)
	if !ok {
		return nil, fmt.Errorf("session invalid")
	}
	if time.Now().Unix() > iat+3600 {
		return nil, fmt.Errorf("session invalid")
	}
	return session, nil
}

func (h *Handler) asLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "aslogin.html", map[string]any{})
		return
	}

	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	ia, err := addr.ParseIA(username)
	dbUser, err := h.store.GetASUser(r.Context(), ia)
	if err != nil {
		log.Debug("AS login handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if dbUser == nil {
		templates.ExecuteTemplate(w, "aslogin.html", map[string]any{
			"Error": "invalid credentials",
		})
		return
	}
	err = bcrypt.CompareHashAndPassword(
		[]byte(dbUser.PasswordHash),
		[]byte(password),
	)
	if err != nil {
		templates.ExecuteTemplate(w, "aslogin.html", map[string]any{
			"Error": "invalid credentials",
		})
		return
	}

	err = h.SetSessionUser(w, r, dbUser.IA)
	if err != nil {
		log.Debug("AS login handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/asbalance", http.StatusSeeOther)
}

func (h *Handler) asBalanceHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.GetSession(r)
	if err != nil {
		http.Redirect(w, r, "/aslogin", http.StatusSeeOther)
		return
	}
	ia, ok := session.Values["user"].(addr.IA)
	if !ok {
		http.Redirect(w, r, "/aslogin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		dbUser, err := h.store.GetASUser(r.Context(), ia)
		if err != nil {
			log.Debug("AS balance handler", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/aslogin", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "asbalance.html", map[string]any{
			"Balance":  strconv.Itoa(int(dbUser.Balance)),
			"Username": ia.String(),
		})
		return
	}
	r.ParseForm()
	deposit := r.FormValue("deposit")
	depositInt, err := strconv.Atoi(deposit)
	if err != nil || depositInt < 0 {
		dbUser, err := h.store.GetASUser(r.Context(), ia)
		if err != nil {
			log.Debug("AS balance handler", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/aslogin", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "asbalance.html", map[string]any{
			"Error":    "Invalid deposit amount",
			"Balance":  strconv.Itoa(int(dbUser.Balance)),
			"Username": ia.String(),
		})
		return
	}

	user, err := h.store.DepositMoneyAndGetAS(r.Context(), ia, int64(depositInt))
	if err != nil {
		log.Debug("AS balance handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	templates.ExecuteTemplate(w, "asbalance.html", map[string]any{
		"Balance":  strconv.Itoa(int(user.Balance)),
		"Username": ia.String(),
	})
}

func (h *Handler) balanceHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.GetSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user, ok := session.Values["user"].(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		dbUser, err := h.store.GetUser(r.Context(), user.ID)
		if err != nil {
			log.Debug("User balance handler", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Username": user.Name,
			"Balance":  strconv.Itoa(int(dbUser.Balance)),
		})
		return
	}
	r.ParseForm()
	deposit := r.FormValue("deposit")
	depositInt, err := strconv.Atoi(deposit)
	if err != nil || depositInt < 0 {
		dbUser, err := h.store.GetUser(r.Context(), user.ID)
		if err != nil {
			log.Debug("User balance handler", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Username": user.Name,
			"Error":    "Invalid deposit amount",
			"Balance":  strconv.Itoa(int(dbUser.Balance)),
		})
		return
	}
	dbUser, err := h.store.DepositMoneyAndGet(r.Context(), user.ID, int64(depositInt))
	if err != nil {
		log.Debug("User balance handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	templates.ExecuteTemplate(w, "balance.html", map[string]any{
		"Username": user.Name,
		"Balance":  strconv.Itoa(int(dbUser.Balance)),
	})
}

func (h *Handler) registerHandler(w http.ResponseWriter, r *http.Request) {
	if h.disableUserRegistration {
		templates.ExecuteTemplate(w, "register.html", map[string]any{
			"Error": "User registration disabled",
		})
		return
	}
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "register.html", map[string]any{})
		return
	}

	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.store.GetUserByName(r.Context(), username)
	if err != nil {
		log.Debug("User register handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if user != nil {
		templates.ExecuteTemplate(w, "register.html", map[string]any{
			"Error": "Username already exists",
		})
		return
	}
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		12,
	)
	if err != nil {
		log.Debug("User register handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	userId, err := h.store.CreateUser(r.Context(), &db.DBUser{
		Name:         username,
		PasswordHash: string(hash),
	})
	if err != nil {
		log.Debug("User register handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	err = h.SetSessionUser(w, r, User{
		ID:   userId,
		Name: username,
	})
	if err != nil {
		log.Debug("User register handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/token", http.StatusSeeOther)
}

func (h *Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.GetSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	clear(session.Values)
	session.Options.MaxAge = -1
	err = session.Save(r, w)
	if err != nil {
		log.Debug("Logout handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", map[string]any{})
		return
	}

	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	dbUser, err := h.store.GetUserByName(r.Context(), username)
	if err != nil {
		log.Debug("User login handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if dbUser == nil {
		templates.ExecuteTemplate(w, "login.html", map[string]any{
			"Error": "invalid credentials",
		})
		return
	}
	err = bcrypt.CompareHashAndPassword(
		[]byte(dbUser.PasswordHash),
		[]byte(password),
	)
	if err != nil {
		templates.ExecuteTemplate(w, "login.html", map[string]any{
			"Error": "invalid credentials",
		})
		return
	}

	err = h.SetSessionUser(w, r, User{
		ID:   dbUser.ID,
		Name: username,
	})
	if err != nil {
		templates.ExecuteTemplate(w, "login.html", map[string]any{
			"Error": err.Error(),
		})
		return
	}

	http.Redirect(w, r, "/token", http.StatusSeeOther)
}

func (h *Handler) tokenHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.GetSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user, ok := session.Values["user"].(User)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	dbUser, err := h.store.GetUser(r.Context(), user.ID)
	if err != nil {
		templates.ExecuteTemplate(w, "token.html", map[string]any{
			"Username": user.Name,
			"Error":    err,
		})
		return
	}
	token, err := h.createToken(strconv.FormatInt(user.ID, 10), dbUser.TokenVersion)
	if err != nil {
		log.Debug("User token handler", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "token.html", map[string]any{
			"Username": user.Name,
			"Token":    token,
		})
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(token))
	}

}

func (h *Handler) createToken(user string, tokenVersion int64) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user,
		"scope": "User",
		"exp":   time.Now().Add(time.Hour * 24 * 7).Unix(),
		"iat":   time.Now().Unix(),
		"ver":   tokenVersion,
	}
	return h.signer.GenerateToken(claims)
}
