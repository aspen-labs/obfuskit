FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /app/obfuskit-vuln-app ./waf-testing/obfuskit-vuln-app

FROM gcr.io/distroless/base-debian12
COPY --from=build /app/obfuskit-vuln-app /usr/local/bin/main
EXPOSE 8881
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/main"]

