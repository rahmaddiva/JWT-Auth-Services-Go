package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"jwt_auth_service_go/middleware"
	"jwt_auth_service_go/services"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestJWTMiddleware_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	jwtSvc := services.NewJWTService("secret", "issuer", 15, 7)
	r := gin.New()
	r.GET("/protected", middleware.JWTAuthMiddleware(jwtSvc), func(c *gin.Context) {
		c.String(200, "ok")
	})

	req, _ := http.NewRequest("GET", "/protected", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestJWTMiddleware_WithValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	jwtSvc := services.NewJWTService("secret", "issuer", 15, 7)
	token, _ := jwtSvc.GenerateAccessToken("u1", "alice", "user")

	r := gin.New()
	r.GET("/protected", middleware.JWTAuthMiddleware(jwtSvc), func(c *gin.Context) {
		c.String(200, "ok")
	})

	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "ok", rr.Body.String())
}
