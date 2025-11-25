package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"jwt_auth_service_go/handlers"
	"jwt_auth_service_go/middleware"
	"jwt_auth_service_go/services"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter() (*gin.Engine, *services.JWTService) {
	gin.SetMode(gin.TestMode)

	jwtSvc := services.NewJWTService("testsecret", "issuer", 15, 7)
	authHandler := handlers.NewAuthHandler(jwtSvc)

	r := gin.Default()

	api := r.Group("/api")
	{
		api.POST("/register", authHandler.Register)
		api.POST("/login", authHandler.Login)
		api.POST("/refresh", authHandler.Refresh)

		protected := api.Group("/protected")
		protected.Use(middleware.JWTAuthMiddleware(jwtSvc))
		protected.GET("/me", authHandler.Protected)
	}

	return r, jwtSvc
}


func TestRegister(t *testing.T) {
	r, _ := setupRouter()
	body := `{"username":"alice","password":"12345"}`
	req, _ := http.NewRequest("POST", "/api/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, 201, rr.Code)
}

func TestLoginAndAccessProtected(t *testing.T) {
	r, _ := setupRouter()

	// REGISTER
	regBody := `{"username":"alice","password":"12345"}`
	regReq, _ := http.NewRequest("POST", "/api/register", bytes.NewBufferString(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), regReq)

	// LOGIN
	loginBody := `{"username":"alice","password":"12345"}`
	loginReq, _ := http.NewRequest("POST", "/api/login", bytes.NewBufferString(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")

	loginRR := httptest.NewRecorder()
	r.ServeHTTP(loginRR, loginReq)

	assert.Equal(t, 200, loginRR.Code)

	var loginResp map[string]interface{}
	json.Unmarshal(loginRR.Body.Bytes(), &loginResp)
	accessToken := loginResp["access_token"].(string)

	// ACCESS PROTECTED ENDPOINT
	req, _ := http.NewRequest("GET", "/api/protected/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	assert.Equal(t, 200, rr.Code)
}

func TestRefreshToken(t *testing.T) {
	r, _ := setupRouter()

	// REGISTER
	registerBody := `{"username":"bob","password":"pwd"}`
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/register", bytes.NewBufferString(registerBody)))

	// LOGIN
	loginBody := `{"username":"bob","password":"pwd"}`
	loginReq := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")

	loginRR := httptest.NewRecorder()
	r.ServeHTTP(loginRR, loginReq)

	var loginResp map[string]interface{}
	json.Unmarshal(loginRR.Body.Bytes(), &loginResp)

	refreshToken := loginResp["refresh_token"].(string)

	// REFRESH
	refreshReqBody := `{"refresh_token":"` + refreshToken + `"}`
	refreshReq := httptest.NewRequest("POST", "/api/refresh", bytes.NewBufferString(refreshReqBody))
	refreshReq.Header.Set("Content-Type", "application/json")

	refreshRR := httptest.NewRecorder()
	r.ServeHTTP(refreshRR, refreshReq)

	assert.Equal(t, 200, refreshRR.Code)
}
