package main

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-ozzo/ozzo-validation/v3"
	"github.com/kintohub/session-graphql-actions/internal/config"
	"github.com/machinebox/graphql"
	"github.com/pkg/errors"
	"log"
	"net/http"
	"time"
)

var (
	hasuraClient *graphql.Client
)

type CreateSessionRequest struct {
	ExpiresAt   string `json:"expiresAt"`
	OwnerId     string `json:"ownerId"`
	DefaultRole string `json:"defaultRole"`
}

func (c CreateSessionRequest) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.OwnerId, validation.Required),
		validation.Field(&c.ExpiresAt, validation.Required),
		validation.Field(&c.DefaultRole, validation.Required, validation.By(validDefaultRole)),
	)
}

type Claims struct {
	jwt.StandardClaims
	Hasura HasuraClaims `json:"hasuraClient"`
}

type HasuraClaims struct {
	AllowedRoles []string `json:"x-hasuraClient-allowed-roles"`
	DefaultRole  string   `json:"x-hasuraClient-default-role"`
	SessionId    string   `json:"x-hasuraClient-session-id"`
	OwnerId      string   `json:"x-hasuraClient-owner-id"`
}

type InsertSessionResponse struct {
	InsertedSessions struct {
		Returning []struct {
			Id        string `json:"id"`
			CreatedAt string `json"createdAt"`
			ExpiresAt string `json"expiresAt"`
		} `json:"returning"`
	} `json:"insert_sessions"`
}

func main() {
	hasuraClient = graphql.NewClient(config.HasuraGraphqlEndpoint)

	r := gin.Default()
	r.POST("/createSession", createSessionHandler)
	r.Run("0.0.0.0:3000")
}

func validDefaultRole(role interface{}) error {
	for _, hasuraRole := range config.HasuraRoles {
		if hasuraRole == role {
			return nil
		}
	}

	return errors.New(fmt.Sprintf("Provided invalid role. Valid roles are %v", config.HasuraRoles))
}

func createSessionHandler(c *gin.Context) {
	var request CreateSessionRequest

	if err := c.BindJSON(&request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid json object: " + err.Error()})
	} else if err := request.Validate(); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"data": map[string]string{
				"accessToken": createAccessToken(&request),
			},
		})
	}
}

func createAccessToken(request *CreateSessionRequest) string {

	req := graphql.NewRequest(`
		mutation CreateSession($ownerId: uuid, $expiresAt: timestamptz) {
		  insert_sessions(objects: {ownerId: $ownerId, expiresAt: $expiresAt}) {
			returning {
			  id
			  createdAt
              expiresAt
			}
		  }
		}`)

	req.Var("ownerId", request.OwnerId)
	req.Var("expiresAt", request.ExpiresAt)
	req.Header.Set("X-Hasura-Admin-Secret", config.HasuraAdminSecret)

	var response InsertSessionResponse
	err := hasuraClient.Run(context.Background(), req, &response)

	if err != nil {
		log.Panicf("Error creating session: %v", err)
	}

	return createJwtToken(
		response.InsertedSessions.Returning[0].Id,
		request.OwnerId,
		request.DefaultRole,
		response.InsertedSessions.Returning[0].CreatedAt,
		response.InsertedSessions.Returning[0].ExpiresAt)
}

func createJwtToken(sessionId string, ownerId string, defaultRole string, issuedAt string, expiresAt string) string {
	claims := Claims{
		Hasura: HasuraClaims{
			AllowedRoles: config.HasuraRoles,
			DefaultRole:  defaultRole,
			SessionId:    sessionId,
			OwnerId:      ownerId,
		},
	}

	issuedAtTime, _ := time.Parse(time.RFC3339, issuedAt)
	expiresAtTime, _ := time.Parse(time.RFC3339, expiresAt)

	claims.Id = sessionId
	claims.Issuer = "session-graphql-actions"
	claims.IssuedAt = issuedAtTime.Unix()
	claims.ExpiresAt = expiresAtTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	tokenString, err := token.SignedString([]byte(config.JwtKey))

	if err != nil {
		log.Panicf("Error creating jwt token: %v", err)
	}

	return tokenString
}
