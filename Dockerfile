FROM golang:1.26-bookworm AS source
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
FROM source AS test
RUN test -z "$(gofmt -l cmd internal web/*.go)" && go vet ./... && go test -race -count=1 ./...
FROM source AS build
RUN mkdir -p /out/control /out/delivery /out/data/uploads /out/secrets && chmod 770 /out/control && chmod 700 /out/delivery /out/data /out/data/uploads /out/secrets
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/waypoint ./cmd/waypoint
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=build /out/waypoint /waypoint
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/control /control
COPY --from=build --chown=65532:65532 /out/delivery /delivery
COPY --from=build --chown=65532:65532 /out/secrets /secrets
ENV DATA_DIR=/data LISTEN_ADDR=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/waypoint"]
CMD ["serve"]
