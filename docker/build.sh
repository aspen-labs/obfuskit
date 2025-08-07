#!/bin/bash
# ObfusKit Docker Build Script
# Builds and tags Docker images for different environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="obfuskit"
VERSION="2.1.0"
REGISTRY="${REGISTRY:-}"

echo -e "${BLUE}🐳 ObfusKit Docker Build Script${NC}"
echo "================================="

# Function to build image
build_image() {
    local tag="$1"
    local dockerfile="${2:-Dockerfile}"
    local context="${3:-.}"
    
    echo -e "${YELLOW}📦 Building image: $IMAGE_NAME:$tag${NC}"
    
    docker build \
        --file "$dockerfile" \
        --tag "$IMAGE_NAME:$tag" \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --build-arg VCS_REF="$(git rev-parse HEAD 2>/dev/null || echo 'unknown')" \
        "$context"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Successfully built $IMAGE_NAME:$tag${NC}"
    else
        echo -e "${RED}❌ Failed to build $IMAGE_NAME:$tag${NC}"
        exit 1
    fi
}

# Function to tag image
tag_image() {
    local source_tag="$1"
    local target_tag="$2"
    
    echo -e "${YELLOW}🏷️  Tagging $IMAGE_NAME:$source_tag as $IMAGE_NAME:$target_tag${NC}"
    docker tag "$IMAGE_NAME:$source_tag" "$IMAGE_NAME:$target_tag"
}

# Function to push image
push_image() {
    local tag="$1"
    local full_name="$IMAGE_NAME:$tag"
    
    if [ -n "$REGISTRY" ]; then
        full_name="$REGISTRY/$full_name"
        docker tag "$IMAGE_NAME:$tag" "$full_name"
    fi
    
    echo -e "${YELLOW}📤 Pushing $full_name${NC}"
    docker push "$full_name"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Successfully pushed $full_name${NC}"
    else
        echo -e "${RED}❌ Failed to push $full_name${NC}"
        exit 1
    fi
}

# Parse command line arguments
COMMAND="${1:-build}"
ENV="${2:-latest}"

case "$COMMAND" in
    "build")
        echo -e "${BLUE}🔨 Building Docker images...${NC}"
        
        # Build main image
        build_image "$ENV"
        
        # Tag with version if building latest
        if [ "$ENV" = "latest" ]; then
            tag_image "latest" "$VERSION"
            tag_image "latest" "v$VERSION"
        fi
        
        echo
        echo -e "${GREEN}🎉 Build completed successfully!${NC}"
        echo -e "${YELLOW}📋 Built images:${NC}"
        docker images "$IMAGE_NAME" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
        ;;
        
    "push")
        echo -e "${BLUE}📤 Pushing Docker images...${NC}"
        
        if [ -z "$REGISTRY" ]; then
            echo -e "${RED}❌ REGISTRY environment variable not set${NC}"
            echo "Usage: REGISTRY=your-registry.com $0 push"
            exit 1
        fi
        
        # Push images
        push_image "$ENV"
        
        if [ "$ENV" = "latest" ]; then
            push_image "$VERSION"
            push_image "v$VERSION"
        fi
        
        echo -e "${GREEN}🎉 Push completed successfully!${NC}"
        ;;
        
    "clean")
        echo -e "${BLUE}🧹 Cleaning up Docker images...${NC}"
        
        # Remove images
        docker rmi "$IMAGE_NAME:$ENV" 2>/dev/null || true
        docker rmi "$IMAGE_NAME:$VERSION" 2>/dev/null || true
        docker rmi "$IMAGE_NAME:v$VERSION" 2>/dev/null || true
        
        # Clean up dangling images
        docker image prune -f
        
        echo -e "${GREEN}✅ Cleanup completed${NC}"
        ;;
        
    "test")
        echo -e "${BLUE}🧪 Testing Docker image...${NC}"
        
        # Test basic functionality
        echo -e "${YELLOW}Testing version command...${NC}"
        docker run --rm "$IMAGE_NAME:$ENV" ./obfuskit -version
        
        echo -e "${YELLOW}Testing help command...${NC}"
        docker run --rm "$IMAGE_NAME:$ENV" ./obfuskit -help | head -10
        
        echo -e "${YELLOW}Testing payload generation...${NC}"
        docker run --rm "$IMAGE_NAME:$ENV" ./obfuskit -attack xss -payload '<script>alert(1)</script>' -limit 5
        
        echo -e "${GREEN}✅ All tests passed!${NC}"
        ;;
        
    "run")
        echo -e "${BLUE}🚀 Running ObfusKit container...${NC}"
        
        # Run interactive container
        docker run -it --rm \
            --name obfuskit-interactive \
            -v "$(pwd)/output:/app/output" \
            "$IMAGE_NAME:$ENV" \
            /bin/sh
        ;;
        
    *)
        echo -e "${RED}❌ Unknown command: $COMMAND${NC}"
        echo
        echo "Usage: $0 <command> [environment]"
        echo
        echo "Commands:"
        echo "  build [ENV]    Build Docker image (default: latest)"
        echo "  push [ENV]     Push image to registry"
        echo "  test [ENV]     Test the built image"
        echo "  clean [ENV]    Remove built images"
        echo "  run [ENV]      Run interactive container"
        echo
        echo "Examples:"
        echo "  $0 build latest"
        echo "  REGISTRY=myregistry.com $0 push latest"
        echo "  $0 test latest"
        echo "  $0 run latest"
        exit 1
        ;;
esac
