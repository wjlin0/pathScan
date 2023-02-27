set CGO_ENABLED=0
set GOARCH=amd64
set GOOS=darwin
go build -ldflags="-s -w" -trimpath -o releases/pathScan_darwin
set GOOS=linux
go build -ldflags="-s -w" -trimpath -o releases/pathScan_linux
set GOOS=windows
go build -ldflags="-s -w" -trimpath -o releases/pathScan.exe



