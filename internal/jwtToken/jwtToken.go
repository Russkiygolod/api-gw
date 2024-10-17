package jwttoken

import (
	"log"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

//go:generate mockgen -source=jwtToken.go -destination=mocks/jwt_mock.go -package=mock

type JwtToken interface {
	GetToken(Email string) (string, error)
	VerifyToken(tokenString string) (jwt.Claims, error)
	AuthMiddleware(tokenString string) (string, error)
}

// создаем логгер
var fileError, _ = os.OpenFile("log_Token_error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
var logError = log.New(fileError, "ERROR:", log.LstdFlags|log.Lshortfile)

func GetToken(Email string) (string, error) {
	payload := jwt.MapClaims{
		"sub": Email,
		"exp": time.Now().Add(time.Hour * 72).Unix(),
	}
	signingKey := []byte("keymaker")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		logError.Println(err)
		return "", err
	}
	return tokenString, nil
}

func VerifyToken(tokenString string) (jwt.Claims, error) {
	signingKey := []byte("keymaker")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		logError.Println(err)
		return nil, err
	}
	return token.Claims, nil
}

func AuthMiddleware(tokenString string) (string, error) {
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	claims, err := VerifyToken(tokenString)
	if err != nil {
		logError.Println(err)
		return "", err
	}
	Email := claims.(jwt.MapClaims)["sub"].(string)
	return Email, nil
}
