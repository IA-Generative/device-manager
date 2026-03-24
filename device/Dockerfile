
# Ajout de l'installation de migrate
FROM golang:1.25-alpine AS base

WORKDIR /app

RUN apk add --no-cache git ca-certificates

# Installation de migrate via go install (v4.19.1)
RUN go install  -tags "postgres,mysql" github.com/golang-migrate/migrate/v4/cmd/migrate@v4.19.1

COPY device/go.mod device/go.sum ./
RUN go mod download


FROM base AS dev

COPY device/go.mod device/go.sum ./
RUN go mod download
RUN go install github.com/air-verse/air@latest

COPY device/ /app/

# migrate déjà présent dans /go/bin (ajouté au PATH par défaut dans l'image golang)

EXPOSE 8080


# Lancement de migrate avant air en dev (exemple, à adapter si besoin)
CMD migrate -path /app/migrations -database "$DATABASE_URL" up && air -c .air.toml



FROM base AS builder

WORKDIR /app/device
COPY ./device .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/device/device-service ./cmd/server
# Build entrypoint
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/device/entrypoint ./entrypoint.go


FROM scratch AS prod



COPY --from=builder /app/device/device-service /device-service
COPY --from=builder /app/device/entrypoint /entrypoint
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /go/bin/migrate /usr/local/bin/migrate
COPY --from=builder /app/device/migrations /migrations
COPY --from=builder /app/device/templates /templates

EXPOSE 8080


# Lancement de migrate puis de l'app via le binaire entrypoint
ENTRYPOINT ["/entrypoint"]