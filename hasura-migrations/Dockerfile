FROM alpine:3.11

WORKDIR /app

COPY config.yaml .
COPY hasura-dev-linux .
COPY /migrations ./migrations

RUN chmod +x hasura-dev-linux

ENTRYPOINT ./hasura-dev-linux migrate apply --endpoint=${HASURA_GRAPHQL_HOST} --admin-secret=${HASURA_GRAPHQL_ADMIN_SECRET}
