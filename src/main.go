package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	fmt.Println("TEst")

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"info": "ok",
		})
	})

	r.POST("/authentication", func(c *gin.Context) {
		var u User
		if err := c.BindJSON(&u); err != nil {
			c.JSON(http.StatusUnprocessableEntity, "Invalid json provider")
			return
		}
		fmt.Println(u.Username, u.Password)

		token, err := CreateToken(u.Username)

		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			return
		}

		c.JSON(http.StatusOK, token)
	})

	r.Run()
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

func CreateToken(userID string) (*TokenDetails, error) {
	tokenData := &TokenDetails{}

	tokenData.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	tokenData.AccessUuid = uuid.New().String()

	tokenData.RtExpires = time.Now().Add(time.Hour * 24).Unix()
	tokenData.RefreshUuid = uuid.New().String()

	var err error
	os.Setenv("ACCESS_SECRET", "123456789")

	atclaims := jwt.MapClaims{}
	atclaims["authorize"] = true
	atclaims["user_id"] = userID
	atclaims["exp"] = tokenData.AtExpires
	atclaims["tokenType"] = "access_token"

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atclaims)
	acccessToken, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

	if err != nil {
		return nil, err
	}

	tokenData.AccessToken = acccessToken

	os.Setenv("REFRESH_SECRET", "123456789")

	rtclaims := jwt.MapClaims{}
	rtclaims["authorize"] = true
	rtclaims["user_id"] = userID
	rtclaims["exp"] = tokenData.RtExpires
	rtclaims["tokenType"] = "refresh_token"

	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtclaims)
	refreshToken, err := rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))

	if err != nil {
		return nil, err
	}

	tokenData.RefreshToken = refreshToken

	return tokenData, nil

}
