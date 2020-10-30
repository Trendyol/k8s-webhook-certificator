ARG GOVERSION=1.15.0
FROM golang:$GOVERSION as builder

ARG VCS_REF
ARG BUILD_TIME

LABEL org.opencontainers.image.authors="trendyoltech" \
org.opencontainers.image.title="Trendyol Certificator" \
org.opencontainers.image.description="Creating K8S Secret which type is tls that includes corresponding client certificates which is signed by K8S CA and private key" \
org.opencontainers.image.vendor="Trendyol" \
org.opencontainers.image.revision=$VCS_REF \
org.opencontainers.image.created=$BUILD_TIME \
org.opencontainers.image.source="https://github.com/Trendyol/k8s-webhook-certificator"

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY ./ ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v .

FROM scratch

COPY --from=builder /app/k8s-webhook-certificator ./k8s-webhook-certificator

ENTRYPOINT ["./k8s-webhook-certificator"]