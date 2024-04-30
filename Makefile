all: validate validate-local
validate: main.go
	env GOOS=linux GOARCH=amd64 go build -ldflags "-w" -o validate
validate-local: main.go
	go build -o validate-local
