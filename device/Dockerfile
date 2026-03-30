
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


# ── Frontend build stage ────────────────────────────────────────────────────
# Build the frontend inside the backend image build context so the final
# backend image contains the static assets at /static. This avoids creating a
# separate frontend image and fits the "copy directly into backend" request.
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm i --frozen-lockfile
COPY frontend/ .
ARG VITE_API_URL=http://localhost:8080
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build
# Ensure files are world-readable for arbitrary UIDs (OpenShift)
RUN chmod -R a+rX /app/frontend/dist


FROM scratch AS prod



COPY --from=builder /app/device/device-service /device-service
COPY --from=builder /app/device/entrypoint /entrypoint
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /go/bin/migrate /usr/local/bin/migrate
COPY --from=builder /app/device/migrations /migrations
COPY --from=builder /app/device/templates /templates
COPY --from=frontend-builder /app/frontend/dist /static

EXPOSE 8080


# Lancement de migrate puis de l'app via le binaire entrypoint
ENTRYPOINT ["/entrypoint"]