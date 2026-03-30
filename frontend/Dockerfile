# ── Build stage ──────────────────────────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm i --frozen-lockfile
COPY . .
ARG VITE_API_URL=http://localhost:8080
ENV VITE_API_URL=${VITE_API_URL}
RUN npm run build

# ── Serve stage (OpenShift-friendly non-root nginx) ─────────────────────────────
# Use the official unprivileged nginx image which runs as a non-root user and
# listens on 8080 in the unprivileged variant. This is safer for OpenShift
# where containers often run with an arbitrary high UID.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
