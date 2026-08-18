# syntax=docker/dockerfile:1.7
FROM node:24-alpine AS frontend
WORKDIR /src
COPY frontend/package*.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM golang:1.24-alpine AS backend
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/jolt-control ./cmd/jolt-control

FROM alpine:3.22
RUN apk add --no-cache ca-certificates libgcc su-exec
COPY --from=backend /out/jolt-control /usr/local/bin/jolt-control
COPY --from=frontend /src/dist /opt/jolt-control/frontend
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
ENV CONTROL_TOWER_DATA_DIR=/var/lib/jolt-control
ENV CONTROL_TOWER_STATIC_DIR=/opt/jolt-control/frontend
EXPOSE 8090
VOLUME ["/var/lib/jolt-control"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/jolt-control"]
