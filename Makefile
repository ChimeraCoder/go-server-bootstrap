compile:
	go build -o build/a.out server.go auth.go conf.go mongodb.go user.go

clean:
	go clean
	find build/ -name *.out -delete
