package services

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	secretKey    string
	issuer       string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

type JwtClaims struct {
	UserID  string `json:"user_id"`
	Username string `json:"username"`
	Role    string `json:"role"`
	jwt.RegisteredClaims
}

func NewJWTService(secretKey, issuer string, accessExpMin, refreshExpDays int) *JWTService {
	return &JWTService{
		secretKey:    secretKey,
		issuer:       issuer,
		accessExpiry:  time.Duration(accessExpMin) * time.Minute,
		refreshExpiry: time.Duration(refreshExpDays) * 24 * time.Hour,
	}
}

func (s *JWTService) GenerateAccessToken(userID, username, role string) (string, error) {
	now := time.Now()
	claims := &JwtClaims{
		UserID:  userID,
		Username: username,
		Role:    role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessExpiry)),
			Subject: userID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secretKey))
}

func (s *JWTService) GenerateRefreshToken(userID, username, role string) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshExpiry)),
		Subject: userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secretKey))
}

func (s *JWTService) ValidateToken(tokenStr string) (*JwtClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
