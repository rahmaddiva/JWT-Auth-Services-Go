package models

import	"time"

type User struct {
	ID string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role string `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}