package controller

import (
	"golang-jwt/model"
	util "golang-jwt/util"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Register(context *gin.Context) {
	var input model.AuthenticationInput

	if err := context.ShouldBindJSON(&input); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := model.User{
		Username: input.Username,
		Password: input.Password,
	}

	savedUser, err := user.Save()

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessToken, refreshToken, err := util.GenerateTokenPair(user)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	context.JSON(http.StatusCreated, gin.H{
		"user":         savedUser,
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func Login(context *gin.Context) {
	var input model.AuthenticationInput

	if err := context.ShouldBindJSON(&input); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := model.FindUserByUsername(input.Username)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(user.Username) < 1 {
		context.JSON(http.StatusBadRequest, gin.H{"error": "ไม่พบผู้ใช้ในระบบ"})
		return
	}

	err = user.ValidatePassword(input.Password)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "รหัสผ่านไม่ถูกต้อง"})
		return
	}

	accessToken, refreshToken, err := util.GenerateTokenPair(user)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	context.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func Refresh(context *gin.Context) {
	var input model.RefreshTokenInput

	if err := context.ShouldBindJSON(&input); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := util.ValidateRefreshJWT(input)
	if err != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		context.Abort()
		return
	}

	userId := uint(claims["id"].(float64))

	user, err := model.FindUserById(userId)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessToken, refreshToken, err := util.GenerateTokenPair(user)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	context.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func GetProfile(context *gin.Context) {
	userId, err := util.CurrentUserId(context)
	if userId == 0 {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		context.Abort()
		return
	}

	user, err := model.FindUserDetailById(userId)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	context.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}
