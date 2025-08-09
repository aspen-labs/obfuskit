FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/obfuskit-vuln-app ./

FROM alpine:3
WORKDIR /app
COPY static /app/static
COPY files /app/files
COPY --from=build /app/obfuskit-vuln-app /usr/local/bin/main

EXPOSE 8881
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/main"]

