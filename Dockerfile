FROM golang:1.27.3 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /aka-vecgen ./cmd/aka-vecgen

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /aka-vecgen /aka-vecgen
ENTRYPOINT ["/aka-vecgen"]
CMD ["serve"]
