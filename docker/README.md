# ObfusKit Docker Deployment

This directory contains Docker configuration files and scripts for containerized deployment of ObfusKit.

## 🐳 Quick Start

### Build and Run

```bash
# Build the Docker image
./docker/build.sh build

# Run a quick test
docker run --rm obfuskit:latest ./obfuskit -version

# Run with volume mounting for output
docker run --rm -v $(pwd)/output:/app/output obfuskit:latest \
    ./obfuskit -attack xss -payload '<script>alert(1)</script>' -limit 10 -output /app/output/results.json
```

### Using Docker Compose

```bash
# Start the full stack
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f obfuskit

# Stop services
docker-compose down
```

## 📁 Files Overview

### Core Files
- **`Dockerfile`** - Multi-stage Docker build configuration
- **`docker-compose.yml`** - Complete stack with ObfusKit, Redis, and Nginx
- **`.dockerignore`** - Files to exclude from Docker build context

### Configuration
- **`nginx.conf`** - Nginx reverse proxy configuration with SSL
- **`build.sh`** - Comprehensive build and management script

## 🚀 Deployment Options

### 1. Standalone Container

**Basic Usage:**
```bash
docker run --rm obfuskit:latest ./obfuskit -attack xss -payload '<script>alert(1)</script>'
```

**With Volume Mounting:**
```bash
docker run --rm \
    -v $(pwd)/custom-payloads:/app/custom-payloads:ro \
    -v $(pwd)/output:/app/output:rw \
    obfuskit:latest \
    ./obfuskit -attack xss -payload-file /app/custom-payloads/custom.txt -output /app/output/results.json
```

**Interactive Mode:**
```bash
docker run -it --rm obfuskit:latest /bin/sh
```

### 2. Server Mode

**Run as Web Service:**
```bash
docker run -d \
    --name obfuskit-server \
    -p 8080:8080 \
    obfuskit:latest \
    ./obfuskit -server
```

**With Custom Configuration:**
```bash
docker run -d \
    --name obfuskit-server \
    -p 8080:8080 \
    -v $(pwd)/config:/app/config:ro \
    obfuskit:latest \
    ./obfuskit -server -config /app/config/server.yaml
```

### 3. Docker Compose Stack

The `docker-compose.yml` provides a complete stack with:

- **ObfusKit Application** - Main testing engine
- **Redis** - Caching layer for improved performance
- **Nginx** - Reverse proxy with SSL termination and load balancing

**Configuration:**
```yaml
services:
  obfuskit:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./output:/app/output:rw
      - ./custom-configs:/app/custom-configs:ro
    environment:
      - OBFUSKIT_MODE=server
```

## 🔧 Build Script Usage

The `build.sh` script provides comprehensive Docker management:

### Build Commands
```bash
# Build latest image
./docker/build.sh build

# Build specific environment
./docker/build.sh build dev

# Build and tag with version
./docker/build.sh build production
```

### Test Commands
```bash
# Test the built image
./docker/build.sh test

# Test specific functionality
./docker/build.sh test latest
```

### Push Commands
```bash
# Push to registry (requires REGISTRY env var)
REGISTRY=myregistry.com ./docker/build.sh push

# Push specific tag
REGISTRY=myregistry.com ./docker/build.sh push v2.1.0
```

### Utility Commands
```bash
# Run interactive container
./docker/build.sh run

# Clean up images
./docker/build.sh clean
```

## 🌐 Production Deployment

### Prerequisites

1. **SSL Certificates** - Place in `docker/ssl/`:
   ```
   docker/ssl/obfuskit.crt
   docker/ssl/obfuskit.key
   ```

2. **Configuration Files** - Create in `custom-configs/`:
   ```
   custom-configs/server.yaml
   custom-configs/production.yaml
   ```

### Deployment Steps

1. **Prepare Environment:**
   ```bash
   # Create necessary directories
   mkdir -p output custom-payloads custom-configs docker/ssl
   
   # Set up SSL certificates
   cp your-certificates/* docker/ssl/
   ```

2. **Configure Services:**
   ```bash
   # Edit docker-compose.yml for your environment
   vim docker-compose.yml
   
   # Create server configuration
   cat > custom-configs/server.yaml << EOF
   action: "Generate Payloads"
   attack_type: "generic"
   evasion_level: "Advanced"
   target:
     method: "File"
     file: "/app/output/server_results.json"
   report_type: "JSON"
   EOF
   ```

3. **Deploy Stack:**
   ```bash
   # Start services
   docker-compose up -d
   
   # Check health
   docker-compose ps
   docker-compose logs
   ```

4. **Verify Deployment:**
   ```bash
   # Test HTTP endpoint
   curl http://localhost/health
   
   # Test HTTPS endpoint (if SSL configured)
   curl https://localhost/health
   
   # Test ObfusKit API
   curl http://localhost:8080/api/version
   ```

## 📊 Monitoring and Logging

### Container Logs
```bash
# View all logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f obfuskit
docker-compose logs -f nginx
docker-compose logs -f redis
```

### Health Checks
```bash
# Check container health
docker-compose ps

# Manual health check
docker exec obfuskit-app ./obfuskit -version
```

### Resource Monitoring
```bash
# Monitor resource usage
docker stats obfuskit-app

# View detailed container info
docker inspect obfuskit-app
```

## 🔒 Security Considerations

### Container Security
- Runs as non-root user (`obfuskit:1000`)
- Minimal attack surface with Alpine Linux base
- Read-only filesystem where possible
- Resource limits configured

### Network Security
- Internal network isolation
- SSL/TLS encryption
- Rate limiting via Nginx
- Security headers configured

### Data Security
- Volume mounts for persistent data
- Secure secrets management
- Log sanitization

## 🚨 Troubleshooting

### Common Issues

**1. Build Failures**
```bash
# Clean Docker cache
docker builder prune -f

# Rebuild without cache
docker build --no-cache -t obfuskit:latest .
```

**2. Permission Issues**
```bash
# Fix volume permissions
sudo chown -R 1000:1000 output/
```

**3. Network Issues**
```bash
# Check network connectivity
docker network ls
docker network inspect obfuskit_obfuskit-network
```

**4. SSL Certificate Issues**
```bash
# Verify certificate files
ls -la docker/ssl/
openssl x509 -in docker/ssl/obfuskit.crt -text -noout
```

### Debug Commands
```bash
# Enter running container
docker exec -it obfuskit-app /bin/sh

# Check container logs
docker logs obfuskit-app

# Inspect container
docker inspect obfuskit-app
```

## 📈 Performance Tuning

### Resource Allocation
```yaml
# In docker-compose.yml
deploy:
  resources:
    limits:
      memory: 1G
      cpus: '2.0'
    reservations:
      memory: 512M
      cpus: '1.0'
```

### Caching Optimization
```yaml
# Redis configuration
redis:
  command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
```

### Nginx Optimization
```nginx
# In nginx.conf
worker_processes auto;
worker_connections 2048;
keepalive_timeout 65;
```

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
name: Build and Deploy
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build Docker image
        run: ./docker/build.sh build
      - name: Test image
        run: ./docker/build.sh test
      - name: Push to registry
        run: REGISTRY=${{ secrets.REGISTRY }} ./docker/build.sh push
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: obfuskit
spec:
  replicas: 3
  selector:
    matchLabels:
      app: obfuskit
  template:
    metadata:
      labels:
        app: obfuskit
    spec:
      containers:
      - name: obfuskit
        image: obfuskit:latest
        ports:
        - containerPort: 8080
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## 📞 Support

For Docker-specific issues:
1. Check container logs: `docker-compose logs`
2. Verify configuration: `docker-compose config`
3. Test connectivity: `docker exec -it obfuskit-app /bin/sh`
4. Review resource usage: `docker stats`

For application issues, refer to the main ObfusKit documentation.
