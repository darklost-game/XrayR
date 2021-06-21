```

git clone https://github.com/XrayR-project/XrayR
cd XrayR/main
go mod tidy
go build -o XrayR -ldflags "-s -w"
./XrayR -config config.yml


nohup ./XrayR -config config.yml >> output.log 2>&1 &
```