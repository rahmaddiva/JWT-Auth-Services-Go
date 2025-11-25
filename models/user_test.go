package models_test

import (
	"testing"
	"jwt_auth_service_go/models"
	"github.com/stretchr/testify/assert"
	"time"
)

func TestUserModel(t *testing.T) {
	now := time.Now()
	user := models.User{
		ID:        "u123",
		Username:  "testuser",
		Password:  "hashedpass",
		Role:      "user",
		CreatedAt: now,
	}

	assert.Equal(t, "u123", user.ID)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "hashedpass", user.Password)
	assert.Equal(t, "user", user.Role)
	assert.Equal(t, now, user.CreatedAt)
}
