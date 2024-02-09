# Build
FROM golang:1.21.0-alpine AS builder
RUN apk add build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build cmd/pathScan/pathScan.go

FROM alpine:3.18.3
RUN apk add bind-tools ca-certificates
COPY --from=builder /app/pathScan /usr/local/bin/pathScan
RUN pathScan

ENTRYPOINT ["pathScan"]
