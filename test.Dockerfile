FROM golang:1.13-buster

COPY go.* ./pwned-passwords/

WORKDIR ./pwned-passwords/

RUN go mod download
