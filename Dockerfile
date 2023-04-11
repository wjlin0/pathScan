FROM golang:1.19-alpine AS builder
ENV CGO_ENABLED=0
RUN  apk add --no-cache git && git clone https://github.com/wjlin0/pathScan.git && cd pathScan && go build -ldflags="-w -s" && unzip -d /tmp/dict/ ./config/dict.zip
FROM alpine:3.17.1
COPY --from=builder /go/pathScan/pathScan /usr/local/bin/pathScan
COPY --from=builder /tmp/dict/ /root/.config/pathScan/dict
COPY --from=builder /go/pathScan/config/match-config.yaml /root/.config/pathScan/match-config.yaml
RUN pathScan

ENTRYPOINT ["pathScan"]
