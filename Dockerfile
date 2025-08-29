# ---------- build stage ----------
FROM golang:1.23-alpine AS builder
WORKDIR /src

# Cache deps first
COPY go.mod go.sum ./
# allow go to auto-fetch newer toolchain if needed (harmless on 1.23)
ENV GOTOOLCHAIN=auto
RUN go mod download

# Copy source
COPY . .

# Build static binary
ENV CGO_ENABLED=0
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/geo-blitz .

# ---------- runtime stage ----------
FROM gcr.io/distroless/static:nonroot
WORKDIR /app

COPY --from=builder /out/geo-blitz /app/geo-blitz
COPY --from=builder /src/data/ /app/data/

ENV ADDR=":8080" \
    MMDB_PATH="/app/data/GeoLite2-City.mmdb" \
    IP2L_BIN_PATH="/app/data/IP2LOCATION-LITE-DB11.BIN" \
    TRUST_XFF="false" \
    ALLOW_PRIVATE_IPS="false" \
    CACHE_SIZE="200000" \
    REQ_TIMEOUT_MS="80" \
    RATE_RPS="50" \
    RATE_BURST="100" \
    RATE_CACHE="200000"

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/geo-blitz"]
