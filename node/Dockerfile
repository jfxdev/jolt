# syntax=docker/dockerfile:1.7
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY backend ./backend
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/jolt-node ./backend/cmd/jolt-node

FROM alpine:3.22
RUN apk add --no-cache ca-certificates su-exec
COPY --from=build /out/jolt-node /usr/local/bin/jolt-node
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
ENV JOLT_DATA_DIR=/var/lib/jolt
ENV JOLT_KEYS_DIR=/var/lib/jolt-keys
EXPOSE 8080 8443
VOLUME ["/var/lib/jolt", "/var/lib/jolt-keys"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/jolt-node"]
