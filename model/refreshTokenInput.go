package model

type RefreshTokenInput struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}
