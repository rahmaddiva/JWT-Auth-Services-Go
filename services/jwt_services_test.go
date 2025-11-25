package services_test

import (
	"testing"
	"jwt_auth_service_go/services"
	"github.com/stretchr/testify/assert"
)

func TestJWTGenerateAndValidate(t *testing.T) {
	jwtSvc := services.NewJWTService("testsecret", "testissuer", 15, 7)

	token, err := jwtSvc.GenerateAccessToken("u123", "alice", "user")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := jwtSvc.ValidateToken(token)
	assert.NoError(t, err)
	assert.Equal(t, "u123", claims.UserID)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "user", claims.Role)
}
