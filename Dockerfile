FROM golang:1.20-alpine AS builder
ENV CGO_ENABLED=0
RUN  go install -v github.com/wjlin0/pathScan@latest
FROM alpine:3.17.1
COPY --from=builder /go/bin/pathScan /usr/local/bin/pathScan
RUN apk add --no-cache libc6-pcap-dev \
    && pathScan

ENTRYPOINT ["pathScan"]
