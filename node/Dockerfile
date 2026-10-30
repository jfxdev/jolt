# syntax=docker/dockerfile:1.7
FROM golang:1.26.10-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY backend ./backend
ARG JOLT_VERSION=development
ARG JOLT_COMMIT=unknown
ARG JOLT_BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath \
    -ldflags="-s -w -X github.com/jfxdev/jolt/backend/internal/buildinfo.Version=${JOLT_VERSION} -X github.com/jfxdev/jolt/backend/internal/buildinfo.Commit=${JOLT_COMMIT} -X github.com/jfxdev/jolt/backend/internal/buildinfo.Date=${JOLT_BUILD_DATE}" \
    -o /out/jolt-node ./backend/cmd/jolt-node

FROM alpine:3.22
ARG JOLT_VERSION=development
ARG JOLT_COMMIT=unknown
ARG JOLT_BUILD_DATE=unknown
LABEL org.opencontainers.image.version="${JOLT_VERSION}" \
      org.opencontainers.image.revision="${JOLT_COMMIT}" \
      org.opencontainers.image.created="${JOLT_BUILD_DATE}"
RUN apk add --no-cache ca-certificates su-exec
COPY --from=build /out/jolt-node /usr/local/bin/jolt-node
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
ENV JOLT_CONFIG_FILE=/etc/jolt/node.yaml
ENV JOLT_DATA_DIR=/var/lib/jolt
ENV JOLT_KEYS_DIR=/var/lib/jolt-keys
EXPOSE 8080 8443
VOLUME ["/var/lib/jolt", "/var/lib/jolt-keys"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/jolt-node"]
