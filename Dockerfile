FROM golang:1.25.4-alpine AS builder


WORKDIR /app

RUN apk add --no-cache build-base

COPY go.mod ./
RUN go mod tidy
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o server ./cmd/main.go

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/server .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Veri klasörü DB için gerekli
RUN mkdir -p data

EXPOSE 8080

CMD ["./server"]