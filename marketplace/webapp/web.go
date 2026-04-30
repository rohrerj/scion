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
	"github.com/scionproto/scion/pkg/addr"
)

var templates = template.Must(template.ParseGlob("marketplace/templates/*.html"))

func Init(signer *marketplace.Signer, mux *http.ServeMux) {
	h := &Handler{
		users:    make(map[string]User),
		sessions: make(map[string]string),
		signer:   signer,
	}
	mux.HandleFunc("/", h.tokenHandler)
	mux.HandleFunc("/login", h.loginHandler)
	mux.HandleFunc("/register", h.registerHandler)
}

type User struct {
	Username string
	Password string
}

type Handler struct {
	users    map[string]User
	sessions map[string]string
	mu       sync.Mutex
	signer   *marketplace.Signer
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

	u := User{
		Username: username,
		Password: password,
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.users[u.Username]; exists {
		templates.ExecuteTemplate(w, "register.html", map[string]any{
			"Error": "Username already exists",
		})
		return
	}

	h.users[u.Username] = u
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

	u := User{
		Username: username,
		Password: password,
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	stored, exists := h.users[u.Username]
	if !exists || stored.Password != u.Password {
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
	_, err := addr.ParseIA(username)
	isUser := err != nil
	token, err := h.createToken(username, isUser)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
	}

	templates.ExecuteTemplate(w, "token.html", map[string]any{
		"Token":       token,
		"IsUserToken": isUser,
	})
}

func (h *Handler) createToken(sub string, isUser bool) (string, error) {
	var claims jwt.MapClaims
	if isUser {
		claims = jwt.MapClaims{
			"sub":   sub,
			"scope": "User",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}
	} else {
		claims = jwt.MapClaims{
			"sub":   sub,
			"scope": "AS",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		}
	}

	return h.signer.GenerateToken(claims)
}
