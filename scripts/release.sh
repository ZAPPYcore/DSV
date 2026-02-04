#!/bin/bash
#
# DSV Release Script
#
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 1.0.0
#

set -euo pipefail

VERSION="${1:-}"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z"
    exit 1
fi

echo "=== DSV Release v$VERSION ==="

# Check working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: Working directory is not clean"
    exit 1
fi

# Check we're on main branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "Warning: Not on main branch (currently on $BRANCH)"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update version in CMakeLists.txt
echo "Updating version in CMakeLists.txt..."
sed -i "s/project(dsv VERSION [0-9]\+\.[0-9]\+\.[0-9]\+/project(dsv VERSION $VERSION/" CMakeLists.txt

# Update version in package.json
echo "Updating version in explorer/web/package.json..."
cd explorer/web
npm version $VERSION --no-git-tag-version
cd ../..

# Commit version changes
git add CMakeLists.txt explorer/web/package.json
git commit -m "Bump version to $VERSION"

# Create tag
echo "Creating tag v$VERSION..."
git tag -a "v$VERSION" -m "Release v$VERSION"

# Build and test
echo "Building..."
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc)
ctest --output-on-failure
cd ..

# Create release artifacts
echo "Creating release artifacts..."
RELEASE_DIR="release/dsv-$VERSION-linux-amd64"
mkdir -p "$RELEASE_DIR"

cp build/dsvd "$RELEASE_DIR/"
cp build/dsv-wallet "$RELEASE_DIR/"
cp build/dsv-cli "$RELEASE_DIR/"
cp -r docs "$RELEASE_DIR/"
cp README.md "$RELEASE_DIR/"
cp LICENSE "$RELEASE_DIR/" 2>/dev/null || echo "No LICENSE file"

# Create archive
cd release
zip -r "dsv-$VERSION-linux-amd64.zip" "dsv-$VERSION-linux-amd64"
sha256sum "dsv-$VERSION-linux-amd64.zip" > "dsv-$VERSION-linux-amd64.zip.sha256"
cd ..

echo ""
echo "=== Release v$VERSION prepared ==="
echo ""
echo "Artifacts created in release/:"
ls -la release/
echo ""
echo "SHA256 checksums:"
cat release/*.sha256
echo ""
echo "Next steps:"
echo "  1. Review the changes: git log -1"
echo "  2. Push changes: git push origin main"
echo "  3. Push tag: git push origin v$VERSION"
echo "  4. GitHub Actions will create the release automatically"

