# Session Graphql Actions

GraphQL Actions is a new concept about attaching logic to graphql queries. This action will create a JWT session for Hasura.

## Warning

Right now actions is in a **preview** state. We have included the custom utilities and cli tools in hasura-migrations folder.

Once actions is out of preview, will standardize this repository to work with a standard hasura graphql engine version

## Project Structure

Using one of the standard go project formats, we have two apps and the database migrations required.

* `/cmd/cleanup-sessions-job` a go app to cleanup expired sessions as a cron job
* `/cmd/session-service` a go microservice to create JWT tokens specifically for hasura graphql engine
* `/hasura-migrations` a custom job to apply hasura database migrations for the services in this project
* `/internal` common code for go apps
* `docker-compose.yaml` sets up hasura, postgres and applies migrations to them

## How to use

* Install go 1.12 or higher
* Install docker 2.x or higher
* Run `docker-compose up -d`
* Run `go mod download && go run ./cmd/session-service`
* Access hasura a http://localhost:8080

## Env Vars

Read the .env-example comments. Copy .env-example as a .env file in the root of this repository
to setup local env variables for testing.

## Functionality

This project is purely for creating generic permission based sessions that can expire.

**Authenticated users can query their own sessions**

```
query {
   sessions {
      id
      createdAt
      expiresAt
      ownerId
      claims
   }
}
```

**Admins (backend services) can create sessions**

```
mutation {
  createSession(
    defaultRole: "user",
    expiresAt:"2020-01-23T07:00:27+00:00",
    ownerId: "395e99fe-e075-4f30-8ef7-dd71bc9c98d5") {
    accessToken
  }
}

```

Admins can also CRUD the entire sessions table itself.
