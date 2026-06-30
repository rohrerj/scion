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
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/marketplace/db"
	"github.com/scionproto/scion/marketplace/storage"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"golang.org/x/crypto/bcrypt"
)

var templates = template.Must(template.ParseGlob("marketplace/templates/*.html"))

func Init(signer *registration.Signer, store *storage.MarketplaceStorage, mux *http.ServeMux) {
	h := &Handler{
		sessions:   make(map[string]User),
		asSessions: make(map[string]addr.IA),
		signer:     signer,
		store:      store,
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
	store      *storage.MarketplaceStorage
	sessions   map[string]User
	asSessions map[string]addr.IA
	mu         sync.Mutex
	signer     *registration.Signer
}
type User struct {
	id   int64
	name string
}

func (h *Handler) getSessionUser(r *http.Request) (User, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return User{}, false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	userId, ok := h.sessions[cookie.Value]
	return userId, ok
}

func (h *Handler) getSessionAS(r *http.Request) (addr.IA, bool) {
	cookie, err := r.Cookie("as_session_id")
	if err != nil {
		return 0, false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	userId, ok := h.asSessions[cookie.Value]
	return userId, ok
}

func (h *Handler) SetSessionUser(sessionId string, user User) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions[sessionId] = user
}

func (h *Handler) SetASSessionUser(sessionId string, user addr.IA) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asSessions[sessionId] = user
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

	sessionID := h.generateSessionID()
	h.SetASSessionUser(sessionID, dbUser.IA)
	http.SetCookie(w, &http.Cookie{
		Name:  "as_session_id",
		Value: sessionID,
		Path:  "/",
	})
	http.Redirect(w, r, "/asbalance", http.StatusSeeOther)
}

func (h *Handler) asBalanceHandler(w http.ResponseWriter, r *http.Request) {
	ia, ok := h.getSessionAS(r)
	if !ok {
		http.Redirect(w, r, "/aslogin", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		dbUser, err := h.store.GetASUser(r.Context(), ia)
		if err != nil {
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
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	templates.ExecuteTemplate(w, "asbalance.html", map[string]any{
		"Balance":  strconv.Itoa(int(user.Balance)),
		"Username": ia.String(),
	})
}

func (h *Handler) balanceHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.getSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		dbUser, err := h.store.GetUser(r.Context(), user.id)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Username": user.name,
			"Balance":  strconv.Itoa(int(dbUser.Balance)),
		})
		return
	}
	r.ParseForm()
	deposit := r.FormValue("deposit")
	depositInt, err := strconv.Atoi(deposit)
	if err != nil || depositInt < 0 {
		dbUser, err := h.store.GetUser(r.Context(), user.id)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Username": user.name,
			"Error":    "Invalid deposit amount",
			"Balance":  strconv.Itoa(int(dbUser.Balance)),
		})
		return
	}
	dbUser, err := h.store.DepositMoneyAndGet(r.Context(), user.id, int64(depositInt))
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	templates.ExecuteTemplate(w, "balance.html", map[string]any{
		"Username": user.name,
		"Balance":  strconv.Itoa(int(dbUser.Balance)),
	})
}

func (h *Handler) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "register.html", map[string]any{})
		return
	}

	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := h.store.GetUserByName(r.Context(), username)
	if err != nil {
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
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	userId, err := h.store.CreateUser(r.Context(), &db.DBUser{
		Name:         username,
		PasswordHash: string(hash),
	})
	if err != nil {
		fmt.Println("Error creating user", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sessionID := h.generateSessionID()
	h.SetSessionUser(sessionID, User{
		id:   userId,
		name: username,
	})

	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	})
	http.Redirect(w, r, "/token", http.StatusSeeOther)
}

func (h *Handler) generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *Handler) logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, cookie.Value)
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	ascookie, err := r.Cookie("as_session_id")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	delete(h.asSessions, ascookie.Value)
	http.SetCookie(w, &http.Cookie{
		Name:   "as_session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// POST /login
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

	sessionID := h.generateSessionID()
	h.SetSessionUser(sessionID, User{
		id:   dbUser.ID,
		name: username,
	})

	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	})

	http.Redirect(w, r, "/token", http.StatusSeeOther)
}

func (h *Handler) tokenHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.getSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "token.html", map[string]any{
			"Username": user.name,
		})
		return
	}
	dbUser, err := h.store.GetUser(r.Context(), user.id)
	if err != nil {
		templates.ExecuteTemplate(w, "token.html", map[string]any{
			"Username": user.name,
			"Error":    err,
		})
		return
	}
	token, err := h.createToken(strconv.FormatInt(user.id, 10), dbUser.TokenVersion)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	templates.ExecuteTemplate(w, "token.html", map[string]any{
		"Username": user.name,
		"Token":    token,
	})
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
