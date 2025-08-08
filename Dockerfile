# ObfusKit Docker Image
# Multi-stage build for optimized production image

# Build stage
FROM golang:1.23.4-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o obfuskit .

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 obfuskit && \
    adduser -D -s /bin/sh -u 1000 -G obfuskit obfuskit

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/obfuskit .

# Copy payload files
COPY --from=builder /app/payloads ./payloads

# Copy example configurations
COPY --from=builder /app/examples ./examples

# Create output directory
RUN mkdir -p /app/output && \
    chown -R obfuskit:obfuskit /app

# Switch to non-root user
USER obfuskit

# Expose default port for server mode
EXPOSE 8181

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ./obfuskit -version || exit 1

# Labels for metadata
LABEL maintainer="Aspen Labs ObfusKit Team" \
      description="Enterprise WAF Testing Platform" \
      version="2.2.0" \
      org.opencontainers.image.title="ObfusKit" \
      org.opencontainers.image.description="Advanced WAF evasion testing tool" \
      org.opencontainers.image.version="2.2.0" \
      org.opencontainers.image.vendor="ObfusKit" \
      org.opencontainers.image.licenses="MIT"


# Default command starts server mode
CMD ["./obfuskit", "-server"]
