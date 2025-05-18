FROM golang:1.22-alpine as builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /main ./cmd/main.go

FROM alpine:latest

WORKDIR /

COPY --from=builder /main /main
COPY --from=builder /app/configs /configs
COPY --from=builder /app/.env .

RUN chmod +x /main

EXPOSE 8080

CMD ["/main"]