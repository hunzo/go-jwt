package services

import (
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/hunzo/go-jwt/entity"
)

func CreateToken(userID string) (*entity.TokenDetails, error) {
	tokenData := &entity.TokenDetails{}

	tokenData.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	// tokenData.AtExpires = time.Now().Add(time.Second * 15).Unix()
	tokenData.AccessUuid = uuid.New().String()

	tokenData.RtExpires = time.Now().Add(time.Hour * 24).Unix()
	// tokenData.RtExpires = time.Now().Add(time.Minute * 5).Unix()
	tokenData.RefreshUuid = uuid.New().String()

	var err error
	os.Setenv("ACCESS_SECRET", "123456789")

	//Create Method 1
	at := jwt.New(jwt.SigningMethodHS256)
	atclaims := make(jwt.MapClaims)
	atclaims["authorize"] = true
	atclaims["user_id"] = userID
	atclaims["exp"] = tokenData.AtExpires
	atclaims["tokenType"] = "access_token"
	atclaims["uuid_access"] = tokenData.AccessUuid
	at.Claims = atclaims

	acccessToken, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

	if err != nil {
		return nil, err
	}

	tokenData.AccessToken = acccessToken

	os.Setenv("REFRESH_SECRET", "123456789")

	//Create Method 2
	rtclaims := jwt.MapClaims{}
	rtclaims["authorize"] = true
	rtclaims["user_id"] = userID
	rtclaims["exp"] = tokenData.RtExpires
	rtclaims["tokenType"] = "refresh_token"
	rtclaims["uuid_access"] = tokenData.RefreshUuid

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtclaims)
	refreshToken, err := rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))

	if err != nil {
		return nil, err
	}

	tokenData.RefreshToken = refreshToken

	return tokenData, nil

}

func ValidateToken(t entity.TokenData) (*jwt.Token, error) {

	tokenString := t.Token

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims)
	} else {
		fmt.Println(err)
	}

	return token, err

}
