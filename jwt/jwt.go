package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	AppName       = "finantierAuthService"
	LoginExp      = time.Duration(24) * time.Hour
	SigningMethod = jwt.SigningMethodHS256
)

type claims struct {
	jwt.StandardClaims
	UserID string
	AppID  string
}

func GenerateToken(UserID string, SignatureKey string) (string, error) {
	c := claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    AppName,
			ExpiresAt: time.Now().Add(LoginExp).Unix(),
		},
		UserID: UserID,
	}

	token := jwt.NewWithClaims(
		SigningMethod,
		c,
	)

	signedToken, err := token.SignedString(SignatureKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil

}

func GenerateTokenExternal(appID, UserID string, SignatureKey string) (string, error) {
	c := claims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    AppName,
			ExpiresAt: time.Now().Add(LoginExp).Unix(),
		},
		AppID:  appID,
		UserID: UserID,
	}

	token := jwt.NewWithClaims(
		SigningMethod,
		c,
	)

	signedToken, err := token.SignedString(SignatureKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func IsValid(tokenJwt string, SignatureKey string) bool {
	token, err := jwt.Parse(tokenJwt, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return false, fmt.Errorf("Signing method invalid")
		} else if method != SigningMethod {
			return false, fmt.Errorf("Signing method invalid")
		}
		return SignatureKey, nil
	})
	if err != nil {
		return false
	}

	_, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return false
	}

	return true
}
