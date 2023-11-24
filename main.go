package main

import (
	"fmt"
	"golang-jwt/controller"
	"golang-jwt/database"
	"golang-jwt/middleware"
	"golang-jwt/model"

	"golang-jwt/util"

	"github.com/gin-gonic/gin"

	"golang-jwt/seed"
)

func main() {
	util.LoadEnv()
	loadDatabase()
	serveApp()
}

func loadDatabase() {
	database.Connect()
	database.Database.AutoMigrate(&model.User{})
	database.Database.AutoMigrate(&model.News{})

	seed.Load(database.Database)
}

func serveApp() {
	router := gin.Default()

	publicRoutes := router.Group("/auth")
	publicRoutes.POST("/register", controller.Register)
	publicRoutes.POST("/login", controller.Login)
	publicRoutes.POST("/refresh", controller.Refresh)

	protectedRoutes := router.Group("/api")
	protectedRoutes.Use(middleware.JWTAuthMiddleware())
	protectedRoutes.GET("/profile", controller.GetProfile)
	protectedRoutes.POST("/news", controller.AddNews)
	protectedRoutes.GET("/news", controller.GetAllNews)

	router.Run(":8090")
	fmt.Println("Server running on port 8090")
}
