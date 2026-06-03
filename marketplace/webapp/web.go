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
	"html/template"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/marketplace"
	"github.com/scionproto/scion/pkg/hummingbird/registration"
)

var templates = template.Must(template.ParseGlob("marketplace/templates/*.html"))

func Init(signer *registration.Signer, accountDB *marketplace.AccountDB, mux *http.ServeMux) {
	h := &Handler{
		sessions:  make(map[string]string),
		signer:    signer,
		accountDB: accountDB,
	}
	mux.HandleFunc("/", h.tokenHandler)
	mux.HandleFunc("/token", h.tokenHandler)
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/register", h.registerHandler)
	mux.HandleFunc("/balance", h.balanceHandler)
}

type Handler struct {
	accountDB *marketplace.AccountDB
	sessions  map[string]string
	mu        sync.Mutex
	signer    *registration.Signer
}

func (h *Handler) getSessionUser(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return "", false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	username, ok := h.sessions[cookie.Value]
	return username, ok
}

func (h *Handler) balanceHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := h.getSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user := h.accountDB.GetUser(username)
	if user == nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Balance": strconv.Itoa(int(user.Balance)),
		})
		return
	}
	r.ParseForm()
	deposit := r.FormValue("deposit")
	depositInt, err := strconv.Atoi(deposit)
	if err != nil || depositInt < 0 {
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Error":   "Invalid deposit amount",
			"Balance": strconv.Itoa(int(user.Balance)),
		})
		return
	}
	user.AddBalance(uint64(depositInt))
	templates.ExecuteTemplate(w, "balance.html", map[string]any{
		"Balance": strconv.Itoa(int(user.Balance)),
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

	u := &marketplace.User{
		Username: username,
		Password: password,
	}
	if !h.accountDB.CreateNonExistingUser(u) {
		templates.ExecuteTemplate(w, "register.html", map[string]any{
			"Error": "Username already exists",
		})
		return
	}

	sessionID := h.generateSessionID()
	h.sessions[sessionID] = u.Username

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

// POST /login
func (h *Handler) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", map[string]any{})
		return
	}

	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	u := &marketplace.User{
		Username: username,
		Password: password,
	}

	dbUser := h.accountDB.GetUser(u.Username)
	if dbUser == nil || dbUser.Password != u.Password {
		templates.ExecuteTemplate(w, "login.html", map[string]any{
			"Error": "invalid credentials",
		})
		return
	}

	sessionID := h.generateSessionID()
	h.sessions[sessionID] = u.Username

	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	})

	http.Redirect(w, r, "/token", http.StatusSeeOther)
}

// GET /request-token
func (h *Handler) tokenHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := h.getSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "token.html", map[string]any{})
		return
	}
	dbUser := h.accountDB.GetUser(username)
	if dbUser == nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	token, err := h.createToken(dbUser)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	templates.ExecuteTemplate(w, "token.html", map[string]any{
		"Token": token,
	})
}

func (h *Handler) createToken(user *marketplace.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.Username,
		"scope": "User",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"ver":   user.TokenVersion,
	}
	return h.signer.GenerateToken(claims)
}
