# Build stage
FROM golang:1.27-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o antigravity-proxy .

FROM alpine:3.22
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/antigravity-proxy /app/antigravity-proxy
EXPOSE 50128
ENTRYPOINT ["/app/antigravity-proxy"]
