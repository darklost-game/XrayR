```

git clone https://github.com/XrayR-project/XrayR
cd XrayR/main
go mod tidy
go build -o XrayR -ldflags "-s -w"
./XrayR -config config.yml

```