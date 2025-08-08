# GitHub Actions Workflows

This directory contains GitHub Actions workflows for building, testing, and publishing ObfusKit Docker images.

## 📋 Available Workflows

### 1. `publish.yml` - GitHub Container Registry
- **Triggers**: Push to main, tags, pull requests
- **Purpose**: Build and publish multi-architecture Docker images to GitHub Container Registry
- **Platforms**: AMD64, ARM64
- **Registry**: `ghcr.io/${{ github.repository }}`

### 2. `publish-dockerhub.yml` - Docker Hub
- **Triggers**: Push to main, tags
- **Purpose**: Build and publish multi-architecture Docker images to Docker Hub
- **Platforms**: AMD64, ARM64
- **Registry**: `docker.io/obfuskit/obfuskit`

### 3. `test.yml` - Testing
- **Triggers**: Pull requests
- **Purpose**: Test builds and run security scans
- **Features**: 
  - Multi-platform Docker builds
  - Go testing with multiple versions
  - Security vulnerability scanning with Trivy

## 🔧 Setup Requirements

### GitHub Container Registry (publish.yml)
- **Automatic**: Uses `GITHUB_TOKEN` (no additional setup required)
- **Permissions**: Repository needs `packages: write` permission

### Docker Hub (publish-dockerhub.yml)
- **Secrets Required**:
  - `DOCKERHUB_USERNAME`: Your Docker Hub username
  - `DOCKERHUB_TOKEN`: Your Docker Hub access token

### Testing (test.yml)
- **Optional Secrets**:
  - `OPENAI_API_KEY`: For testing AI functionality

## 🚀 Usage

### Automatic Publishing
1. **Push to main**: Builds and publishes `latest` tag
2. **Create a tag**: Builds and publishes version-specific tags
   ```bash
   git tag v2.1.0
   git push origin v2.1.0
   ```

### Manual Triggering
```bash
# Trigger workflow manually via GitHub UI
# Go to Actions > Publish Docker Images > Run workflow
```

## 📦 Image Tags

### GitHub Container Registry
- `latest`: Latest build from main
- `v2.1.0`: Specific version tags
- `main-sha-abc123`: Branch-specific builds
- `pr-123`: Pull request builds

### Docker Hub
- `latest`: Latest build from main
- `v2.1.0`: Specific version tags
- `main-sha-abc123`: Branch-specific builds

## 🧪 Testing

### Pull Request Testing
- **Docker Builds**: Tests both AMD64 and ARM64 architectures
- **Go Testing**: Tests with Go 1.21 and 1.22
- **Security Scanning**: Runs Trivy vulnerability scanner
- **AI Testing**: Tests AI functionality if API key is available

### Manual Testing
```bash
# Test AMD64 image
docker run --rm --platform linux/amd64 \
  ghcr.io/${{ github.repository }}:latest \
  ./obfuskit -version

# Test ARM64 image
docker run --rm --platform linux/arm64 \
  ghcr.io/${{ github.repository }}:latest \
  ./obfuskit -version
```

## 🔍 Monitoring

### Workflow Status
- Check Actions tab for workflow status
- View logs for detailed build information
- Monitor security scan results

### Image Health
- **GitHub Container Registry**: View packages in repository settings
- **Docker Hub**: Check repository page for published images

## 🛠️ Troubleshooting

### Common Issues

1. **Build Failures**
   ```bash
   # Check Dockerfile syntax
   docker build --no-cache .
   
   # Verify multi-platform support
   docker buildx build --platform linux/amd64,linux/arm64 .
   ```

2. **Authentication Issues**
   - Verify secrets are set correctly
   - Check repository permissions
   - Ensure tokens have proper scope

3. **Platform-Specific Issues**
   - Test individual platforms separately
   - Check for platform-specific dependencies
   - Verify base image compatibility

### Debug Commands
```bash
# Test local build
docker build -t obfuskit:test .

# Test multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t obfuskit:test .

# Run security scan locally
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image obfuskit:test
```

## 📈 Performance

### Build Optimization
- **Layer Caching**: Uses GitHub Actions cache for faster builds
- **Multi-Platform**: Parallel builds for different architectures
- **Dependency Caching**: Caches Go modules and Docker layers

### Resource Usage
- **Build Time**: ~5-10 minutes for full multi-platform build
- **Cache Size**: ~500MB for Go modules and Docker layers
- **Image Size**: ~50-100MB depending on architecture

## 🔗 Related Files

- `Dockerfile`: Multi-stage Docker build configuration
- `docker-compose.yml`: Local development and testing environment
- `docker/build.sh`: Local build and management script
- `docker/README.md`: Docker-specific documentation
