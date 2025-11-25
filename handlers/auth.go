package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"jwt_auth_service_go/models"
	"jwt_auth_service_go/services"
)

type AuthHandler struct {
	jwtSvc       *services.JWTService
	userStore    map[string]*models.User      // username → User
	refreshStore map[string]string            // refresh_token → userID
}

func NewAuthHandler(jwtSvc *services.JWTService) *AuthHandler {
	return &AuthHandler{
		jwtSvc:       jwtSvc,
		userStore:    make(map[string]*models.User),
		refreshStore: make(map[string]string),
	}
}

type registerRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if _, exists := h.userStore[req.Username]; exists {
		c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
		return
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	id := uuid.NewString()
	user := &models.User{
		ID:        id,
		Username:  req.Username,
		Password:  string(hashed),
		Role:      "user",
		CreatedAt: time.Now(),
	}

	h.userStore[req.Username] = user

	c.JSON(http.StatusCreated, gin.H{"message": "user registered"})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, ok := h.userStore[req.Username]
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	access, _ := h.jwtSvc.GenerateAccessToken(user.ID, user.Username, user.Role)
	refresh, _ := h.jwtSvc.GenerateRefreshToken(user.ID, user.Username, user.Role)

	h.refreshStore[refresh] = user.ID

	c.JSON(http.StatusOK, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "bearer",
	})
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var payload struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := h.jwtSvc.ValidateToken(payload.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	userID, ok := h.refreshStore[payload.RefreshToken]
	if !ok || userID != claims.Subject {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not recognized"})
		return
	}

	user := h.getUserByID(userID)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user no longer exists"})
		return
	}

	access, _ := h.jwtSvc.GenerateAccessToken(user.ID, user.Username, user.Role)

	c.JSON(http.StatusOK, gin.H{
		"access_token": access,
		"token_type":   "bearer",
	})
}

func (h *AuthHandler) Protected(c *gin.Context) {
	raw, _ := c.Get("claims")
	claims := raw.(*services.JwtClaims)

	c.JSON(http.StatusOK, gin.H{
		"message":  "protected data",
		"user_id":  claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
	})
}

func (h *AuthHandler) getUserByID(id string) *models.User {
	for _, u := range h.userStore {
		if u.ID == id {
			return u
		}
	}
	return nil
}
