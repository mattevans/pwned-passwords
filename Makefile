build:
	docker build -t test-pwned-passwords -f test.Dockerfile .

test:
	docker run --volume=$(CURDIR):/go/pwned-passwords/ test-pwned-passwords go test
