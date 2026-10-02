# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o antigravity-proxy .

# Minimal scratch/alpine final image
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/antigravity-proxy /app/antigravity-proxy

EXPOSE 50128

ENTRYPOINT ["/app/antigravity-proxy"]
