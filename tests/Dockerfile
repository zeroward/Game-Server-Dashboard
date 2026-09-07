FROM golang:1.26-bookworm AS fixture
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -tags=e2e -o /testserver ./cmd/e2e
FROM mcr.microsoft.com/playwright:v1.58.2-noble
WORKDIR /work
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY --from=fixture /testserver /testserver
COPY tests/browser.cjs ./tests/browser.cjs
ENTRYPOINT ["node", "/work/tests/browser.cjs"]
