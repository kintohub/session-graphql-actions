package config

import (
	_ "github.com/joho/godotenv/autoload"
	"log"
	"os"
	"strings"
)

var (
	HasuraGraphqlEndpoint string
	HasuraAdminSecret     string
	JwtKey                string
	HasuraRoles           []string
)

func init() {
	HasuraGraphqlEndpoint = os.Getenv("HASURA_GRAPHQL_ENDPOINT")
	JwtKey = os.Getenv("JWT_KEY")
	HasuraRoles = strings.Split(os.Getenv("HASURA_GRAPHQL_ROLES"), ",")
	HasuraAdminSecret = os.Getenv("HASURA_GRAPHQL_ADMIN_SECRET")

	if HasuraGraphqlEndpoint == "" {
		log.Fatal("HASURA_GRAPHQL_ENDPOINT env variable is empty or does not exist")
	}

	if JwtKey == "" {
		log.Fatal("JWT_KEY env variable is empty or does not exist")
	}

	if len(HasuraRoles) == 0 {
		log.Fatal("HASURA_GRAPHQL_ROLES env var must have at least comma separated role. Example: admin,guest")
	}

	if HasuraAdminSecret == "" {
		log.Fatal("HASURA_GRAPHQL_ADMIN_SECRET env var is empty or does not exist")
	}
}
