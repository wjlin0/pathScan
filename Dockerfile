FROM golang:1.19-alpine AS builder
ENV CGO_ENABLED=0
RUN  go install -v github.com/wjlin0/pathScan@latest
FROM alpine:3.17.1
COPY --from=builder /go/bin/pathScan /usr/local/bin/pathScan
RUN pathScan

ENTRYPOINT ["pathScan"]
