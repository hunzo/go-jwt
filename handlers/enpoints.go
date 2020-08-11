package handlers

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/hunzo/go-jwt/entity"
	"github.com/hunzo/go-jwt/services"
)

func PostAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		var u entity.User
		if err := c.BindJSON(&u); err != nil {
			c.JSON(http.StatusUnprocessableEntity, "Invalid json provider")
			return
		}
		fmt.Println(u.Username, u.Password)

		token, err := services.CreateToken(u.Username)

		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			return
		}
		ret := map[string]string{
			"AccessToken":  token.AccessToken,
			"RefreshToken": token.RefreshToken,
		}

		c.JSON(http.StatusOK, ret)
	}

}

func PostValidateToken() gin.HandlerFunc {
	return func(c *gin.Context) {

		var t entity.TokenData

		if err := c.BindJSON(&t); err != nil {
			c.JSON(http.StatusUnprocessableEntity, "Invalid json provider")
			return
		}
		// fmt.Println(t.Token)

		rt, err := services.ValidateToken(t)

		if rt.Valid {
			claimsConvert := rt.Claims.(jwt.MapClaims)
			fmt.Println(claimsConvert)

			if claimsConvert["tokenType"] == "refresh_token" {

				newToken, err := services.CreateToken(fmt.Sprintf("%v", claimsConvert["user_id"])) //convert interface to string fmt.Sprintf("%v", cc["user_id"])

				if err != nil {
					c.JSON(http.StatusUnauthorized, err.Error())
				}

				retNewToken := map[string]string{
					"AccessToken":  newToken.AccessToken,
					"RefreshToken": newToken.RefreshToken,
				}

				c.JSON(http.StatusOK, retNewToken)

			} else {
				c.JSON(http.StatusOK, map[string]string{
					"error": "invalid TokenType",
				})

			}

		} else {
			fmt.Println("Error in Main--------->", err)
			c.JSON(401, gin.H{
				// "error": "signature is invalid",
				"error": err.Error(),
				"info":  err,
			})
		}

	}

}

func PostCheckClaims() gin.HandlerFunc {
	return func(c *gin.Context) {
		var t entity.TokenData

		if err := c.BindJSON(&t); err != nil {
			c.JSON(http.StatusUnprocessableEntity, "Invalid json provider")
			return
		}
		// fmt.Println(t.Token)

		rt, err := services.ValidateToken(t)

		if rt.Valid {
			// claimsConvert := rt.Claims.(jwt.MapClaims)

			c.JSON(http.StatusOK, rt)

		} else {
			// fmt.Println("ERROR in MAIN", err)
			c.JSON(401, gin.H{
				"error": err.Error(),
				"info":  err,
			})
		}

	}

}
