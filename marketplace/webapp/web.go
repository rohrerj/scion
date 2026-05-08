package webapp

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/scionproto/scion/marketplace"
)

var templates = template.Must(template.ParseGlob("marketplace/templates/*.html"))

func Init(signer *marketplace.Signer, accountDB *marketplace.AccountDB, mux *http.ServeMux) {
	h := &Handler{
		sessions:  make(map[string]string),
		signer:    signer,
		accountDB: accountDB,
	}
	mux.HandleFunc("/", h.tokenHandler)
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/register", h.registerHandler)
}

type Handler struct {
	accountDB *marketplace.AccountDB
	sessions  map[string]string
	mu        sync.Mutex
	signer    *marketplace.Signer
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
