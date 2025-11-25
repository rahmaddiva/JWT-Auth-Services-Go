package handlers

import (
	"jwt_auth_service_go/models"
	"jwt_auth_service_go/services"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// simple in-memory store (replace with DB pada produksi)
var users = map[string]*models.User{} // key = username
var refreshStore = map[string]string{} // refreshToken -> userID

type AuthHandler struct {
    jwtSvc *services.JWTService
}

func NewAuthHandler(jwtSvc *services.JWTService) *AuthHandler {
    return &AuthHandler{jwtSvc: jwtSvc}
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
    if _, exists := users[req.Username]; exists {
        c.JSON(http.StatusConflict, gin.H{"error": "username already taken"})
        return
    }

    hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
        return
    }

    id := uuid.NewString()
    usr := &models.User{
        ID:        id,
        Username:  req.Username,
        Password:  string(hashed),
        Role:      "user",
        CreatedAt: time.Now(),
    }
    users[req.Username] = usr
    c.JSON(http.StatusCreated, gin.H{"message": "user registered"})
}

func (h *AuthHandler) Login(c *gin.Context) {
    var req loginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    usr, ok := users[req.Username]
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
        return
    }
    if err := bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(req.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
        return
    }

    access, err := h.jwtSvc.GenerateAccessToken(usr.ID, usr.Username, usr.Role)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
        return
    }
    refresh, err := h.jwtSvc.GenerateRefreshToken(usr.ID, usr.Username, usr.Role)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate refresh token"})
        return
    }

    // store refresh token server-side (in memory here)
    refreshStore[refresh] = usr.ID

    c.JSON(http.StatusOK, gin.H{
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "expires_in":    int(h.jwtSvc.AccessExpiry().Seconds()), // use seconds for expires_in
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
    // validate refresh token
    claims, err := h.jwtSvc.ValidateToken(payload.RefreshToken)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token", "detail": err.Error()})
        return
    }
    // check it exists in store
    if uid, ok := refreshStore[payload.RefreshToken]; !ok || uid != claims.UserID {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not recognized"})
        return
    }

    // create new access and new refresh token, invalidate old refresh
    access, err := h.jwtSvc.GenerateAccessToken(claims.UserID, claims.Username, claims.Role)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate access token"})
        return
    }
    newRefresh, err := h.jwtSvc.GenerateRefreshToken(claims.UserID, claims.Username, claims.Role)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate new refresh token"})
        return
    }
    // remove old refresh token, store new one
    delete(refreshStore, payload.RefreshToken)
    refreshStore[newRefresh] = claims.UserID
    c.JSON(http.StatusOK, gin.H{
        "access_token":  access,
        "refresh_token": newRefresh,
        "token_type":    "bearer",
        "expires_in":    int(h.jwtSvc.AccessExpiry().Seconds()),
    })
}

func (h *AuthHandler) Protected(c *gin.Context) {
    // ambil claims dari context
    raw, exists := c.Get("claims")
    claims, ok := raw.(*services.JwtClaims)
    if !exists || !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing claims"})
        return
    }
    c.JSON(http.StatusOK, gin.H{
        "message":  "protected data",
        "user_id":  claims.UserID,
        "username": claims.Username,
        "role":     claims.Role,
    })
}
