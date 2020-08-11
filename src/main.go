package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hunzo/go-jwt/handlers"
)

func main() {
	fmt.Println("go-jwt-token")

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"_info":                "go-jwt-token",
			"post /authentication": "payload: username, password",
			"post /token/refresh":  "payload: token: (refresh_token)",
			"post /getdata":        "payload: token: (access_token), (refresh_token)",
		})
	})

	r.POST("/authentication", handlers.PostAuthentication())
	r.POST("/token/refresh", handlers.PostValidateToken())
	r.POST("/getdata", handlers.PostCheckClaims())

	r.Run()
}
