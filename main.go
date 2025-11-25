package main

import (
	"log"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"jwt_auth_service_go/handlers"
	"jwt_auth_service_go/middleware"
	"jwt_auth_service_go/services"
)

func main() {
    // load .env jika ada
    _ = godotenv.Load()

    jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        log.Println("WARNING: JWT_SECRET not set, using default insecure secret")
        jwtSecret = "change-me-please"
    }
    issuer := "myapp"
    accessMin := 15
    refreshDays := 7

    if v := os.Getenv("ACCESS_MIN"); v != "" {
        if val, err := strconv.Atoi(v); err == nil {
            accessMin = val
        }
    }
    if v := os.Getenv("REFRESH_DAYS"); v != "" {
        if val, err := strconv.Atoi(v); err == nil {
            refreshDays = val
        }
    }

    jwtSvc := services.NewJWTService(jwtSecret, issuer, accessMin, refreshDays)
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

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    r.Run(":" + port)
}
