# DSV Release Checklist

## Version Format

Versions follow Semantic Versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Consensus-breaking changes, hard forks
- **MINOR**: New features, soft forks, significant improvements
- **PATCH**: Bug fixes, security patches, documentation updates

---

## Pre-Release (T-7 days)

### Code Freeze
- [ ] Feature freeze announced
- [ ] All planned features merged
- [ ] Release branch created: `release/vX.Y.Z`
- [ ] Version number updated in:
  - [ ] CMakeLists.txt
  - [ ] package.json (web)
  - [ ] setup.py (indexer, api)
  - [ ] Dockerfiles

### Testing
- [ ] Full test suite passes
- [ ] ASAN build passes
- [ ] UBSAN build passes
- [ ] Integration tests pass:
  - [ ] Genesis → Mine → Spend → Mine
  - [ ] Reorg handling
  - [ ] Explorer sync
- [ ] Manual testing completed:
  - [ ] Fresh install
  - [ ] Upgrade from previous version
  - [ ] Wallet create/restore
  - [ ] Transaction send/receive

### Security
- [ ] Security audit checklist completed
- [ ] No open critical/high security issues
- [ ] Dependency security scan clean
- [ ] Fuzz testing completed (1M+ iterations)

---

## Pre-Release (T-3 days)

### Documentation
- [ ] CHANGELOG.md updated
- [ ] README.md current
- [ ] All docs reviewed and updated
- [ ] Upgrade instructions written
- [ ] Breaking changes documented

### Build Verification
- [ ] Linux x86_64 build verified
- [ ] Linux arm64 build verified
- [ ] macOS x86_64 build verified
- [ ] macOS arm64 build verified
- [ ] Windows x64 build verified
- [ ] Docker images build successfully

### Staging Deployment
- [ ] Deployed to staging environment
- [ ] Staging tests pass
- [ ] Performance benchmarks acceptable
- [ ] No memory leaks detected

---

## Release Day (T-0)

### Final Checks
- [ ] All tests pass on release branch
- [ ] No blocking issues open
- [ ] Release notes finalized
- [ ] Communication drafted

### Tag & Build
```bash
# Tag the release
git checkout release/vX.Y.Z
git tag -s vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z

# Trigger release build (automated via GitHub Actions)
```

### Artifact Verification
- [ ] All artifacts built successfully:
  - [ ] dsv-node-vX.Y.Z-linux-x86_64.tar.gz
  - [ ] dsv-node-vX.Y.Z-linux-arm64.tar.gz
  - [ ] dsv-node-vX.Y.Z-darwin-x86_64.tar.gz
  - [ ] dsv-node-vX.Y.Z-darwin-arm64.tar.gz
  - [ ] dsv-node-vX.Y.Z-windows-x64.zip
  - [ ] dsv-wallet-vX.Y.Z-*.tar.gz
  - [ ] dsv-explorer-vX.Y.Z.tar.gz
- [ ] SHA256 checksums generated
- [ ] All artifacts signed (GPG)
- [ ] Checksums verified

### Docker Images
- [ ] Images tagged with version
- [ ] Images pushed to registry
- [ ] `latest` tag updated
- [ ] Multi-arch manifest created

---

## Release Publication

### GitHub Release
- [ ] Create release from tag
- [ ] Upload all artifacts
- [ ] Upload checksum file
- [ ] Paste release notes
- [ ] Mark as latest (if applicable)
- [ ] Mark as pre-release (if applicable)

### Docker Registry
```bash
# Verify images
docker pull dsvchain/node:vX.Y.Z
docker pull dsvchain/explorer-indexer:vX.Y.Z
docker pull dsvchain/explorer-api:vX.Y.Z
docker pull dsvchain/explorer-web:vX.Y.Z
```

### Package Repositories
- [ ] Update package repositories (if applicable)
- [ ] Homebrew formula (macOS)
- [ ] APT repository (Debian/Ubuntu)
- [ ] RPM repository (RHEL/Fedora)

---

## Post-Release

### Communication
- [ ] Announcement posted:
  - [ ] Website
  - [ ] Blog
  - [ ] Social media
  - [ ] Mailing list
- [ ] Security advisories published (if applicable)

### Monitoring
- [ ] Monitor error tracking
- [ ] Monitor community channels
- [ ] Watch for regression reports
- [ ] Track adoption metrics

### Cleanup
- [ ] Merge release branch to main
- [ ] Delete release branch
- [ ] Update development version
- [ ] Archive old releases (if needed)

---

## Emergency Hotfix Process

### Criteria for Hotfix
- Critical security vulnerability
- Consensus bug
- Data corruption bug
- Complete functionality breakage

### Hotfix Steps
1. [ ] Create hotfix branch from release tag
2. [ ] Fix the issue (minimal changes)
3. [ ] Test fix thoroughly
4. [ ] Version: X.Y.(Z+1)
5. [ ] Security review (expedited)
6. [ ] Follow normal release steps (accelerated)

---

## Release Notes Template

```markdown
# DSV vX.Y.Z Release Notes

## Highlights
- Major feature 1
- Major feature 2

## Breaking Changes
- Change 1 (migration path: ...)
- Change 2

## New Features
- Feature A (#123)
- Feature B (#456)

## Bug Fixes
- Fix issue X (#789)
- Fix issue Y (#012)

## Security
- Security improvement Z

## Performance
- X% improvement in Y

## Dependencies
- Updated libsodium to 1.0.X
- Updated PostgreSQL driver

## Upgrade Notes
1. Backup your data directory
2. Stop the node
3. Replace binaries
4. Start the node
5. Verify operation

## Checksums
```
SHA256 (dsv-node-vX.Y.Z-linux-x86_64.tar.gz) = ...
SHA256 (dsv-node-vX.Y.Z-linux-arm64.tar.gz) = ...
...
```

## Contributors
- @contributor1
- @contributor2
```

---

## Rollback Procedure

If critical issues are discovered post-release:

1. **Assess Impact**
   - [ ] Determine affected users
   - [ ] Identify severity

2. **Communication**
   - [ ] Alert users to stop upgrade
   - [ ] Provide workaround if possible

3. **Technical Rollback**
   - [ ] Unpublish release (mark as draft)
   - [ ] Recommend previous version
   - [ ] Provide rollback instructions

4. **Fix**
   - [ ] Create hotfix
   - [ ] Expedited testing
   - [ ] Re-release

---

## Version History

| Version | Date | Type | Notes |
|---------|------|------|-------|
| 1.0.0 | YYYY-MM-DD | Major | Initial release |
| ... | ... | ... | ... |

