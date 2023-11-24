package util

import (
	"errors"
	"fmt"
	"golang-jwt/model"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(user model.User) (string, error) {
	tokenTTL, _ := strconv.Atoi(os.Getenv("TOKEN_TTL"))
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  user.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * time.Duration(tokenTTL)).Unix(),
	})
	return token.SignedString([]byte(os.Getenv("JWT_PRIVATE_KEY")))
}

func GenerateRefreshJWT(user model.User) (string, error) {
	TOKEN_TTL_REFRESH, _ := strconv.Atoi(os.Getenv("TOKEN_TTL_REFRESH"))
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  user.ID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * time.Duration(TOKEN_TTL_REFRESH)).Unix(),
	})
	return refreshToken.SignedString([]byte(os.Getenv("JWT_REFRESH_PRIVATE_KEY")))
}

func GenerateTokenPair(user model.User) (string, string, error) {
	accessToken, err := GenerateJWT(user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := GenerateRefreshJWT(user)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func ValidateJWT(context *gin.Context) error {
	token, err := getToken(context)
	if err != nil {
		return err
	}
	_, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		return nil
	}
	return errors.New("invalid token provided")
}

func CurrentUser(context *gin.Context) (model.User, error) {
	err := ValidateJWT(context)
	if err != nil {
		return model.User{}, err
	}
	token, _ := getToken(context)
	claims, _ := token.Claims.(jwt.MapClaims)
	userId := uint(claims["id"].(float64))

	user, err := model.FindUserById(userId)
	if err != nil {
		return model.User{}, err
	}
	return user, nil
}

func CurrentUserId(context *gin.Context) (uint, error) {
	token, err := getToken(context)
	if err != nil {
		return 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		userId := uint(claims["id"].(float64))
		return userId, nil
	}
	return 0, nil
}

func getToken(context *gin.Context) (*jwt.Token, error) {
	tokenString := getTokenFromRequest(context)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("JWT_PRIVATE_KEY")), nil
	})
	return token, err
}

func getTokenFromRequest(context *gin.Context) string {
	bearerToken := context.Request.Header.Get("Authorization")
	splitToken := strings.Split(bearerToken, " ")
	if len(splitToken) == 2 {
		return splitToken[1]
	}
	return ""
}

func ValidateRefreshJWT(input model.RefreshTokenInput) (jwt.MapClaims, error) {
	token, err := GetRefreshToken(input)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token provided")
}

func GetRefreshToken(input model.RefreshTokenInput) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(input.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("JWT_REFRESH_PRIVATE_KEY")), nil
	})

	return parsedToken, err
}
