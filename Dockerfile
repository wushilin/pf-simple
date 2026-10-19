# Cross-compiles on the build machine's platform, so multi-arch images need
# no emulation. The binary is static (CGO off).
FROM --platform=$BUILDPLATFORM golang:1.23 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /pf-simple .

# Runs as root so the redirect listener can bind port 80 with --network host;
# pass --user to run unprivileged.
FROM gcr.io/distroless/static-debian12
COPY --from=build /pf-simple /usr/local/bin/pf-simple
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/pf-simple"]
CMD ["-h"]
