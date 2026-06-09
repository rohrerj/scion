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
	"github.com/scionproto/scion/pkg/hummingbird/registration"
	"golang.org/x/crypto/bcrypt"
)

var templates = template.Must(template.ParseGlob("marketplace/templates/*.html"))

func Init(signer *registration.Signer, store *storage.MarketplaceStorage, mux *http.ServeMux) {
	h := &Handler{
		sessions: make(map[string]int64),
		signer:   signer,
		store:    store,
	}
	mux.HandleFunc("/", h.tokenHandler)
	mux.HandleFunc("/token", h.tokenHandler)
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/register", h.registerHandler)
	mux.HandleFunc("/balance", h.balanceHandler)
}

type Handler struct {
	store    *storage.MarketplaceStorage
	sessions map[string]int64
	mu       sync.Mutex
	signer   *registration.Signer
}

func (h *Handler) getSessionUser(r *http.Request) (int64, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return 0, false
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	userId, ok := h.sessions[cookie.Value]
	return userId, ok
}

func (h *Handler) balanceHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := h.getSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		dbUser, err := h.store.GetUser(r.Context(), username)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Balance": strconv.Itoa(int(dbUser.Balance)),
		})
		return
	}
	r.ParseForm()
	deposit := r.FormValue("deposit")
	depositInt, err := strconv.Atoi(deposit)
	if err != nil || depositInt < 0 {
		dbUser, err := h.store.GetUser(r.Context(), username)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if dbUser == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		templates.ExecuteTemplate(w, "balance.html", map[string]any{
			"Error":   "Invalid deposit amount",
			"Balance": strconv.Itoa(int(dbUser.Balance)),
		})
		return
	}
	user, err := h.store.DepositMoneyAndGet(r.Context(), username, int64(depositInt))
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
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
	h.sessions[sessionID] = userId

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
	h.sessions[sessionID] = dbUser.ID

	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: sessionID,
		Path:  "/",
	})

	http.Redirect(w, r, "/token", http.StatusSeeOther)
}

func (h *Handler) tokenHandler(w http.ResponseWriter, r *http.Request) {
	userId, ok := h.getSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "token.html", map[string]any{})
		return
	}
	token, err := h.createToken(strconv.FormatInt(userId, 10))
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	templates.ExecuteTemplate(w, "token.html", map[string]any{
		"Token": token,
	})
}

func (h *Handler) createToken(user string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user,
		"scope": "User",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		//"ver":   user.TokenVersion,
	}
	return h.signer.GenerateToken(claims)
}
