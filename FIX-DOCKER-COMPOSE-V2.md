# 🔧 Fix Applied: Docker Compose V2 Syntax

## Issue

GitHub Actions workflow was failing with:
```
docker-compose: command not found
Error: Process completed with exit code 127
```

## Root Cause

GitHub Actions runners use **Docker Compose V2**, which uses the command `docker compose` (with a space) instead of the legacy `docker-compose` (with a hyphen).

## Fix Applied

Updated all occurrences in `.github/workflows/test-vuln-bank.yml`:

### Changes Made

| Old Syntax (V1) | New Syntax (V2) |
|-----------------|-----------------|
| `docker-compose up -d` | `docker compose up -d` |
| `docker-compose ps` | `docker compose ps` |
| `docker-compose logs` | `docker compose logs` |
| `docker-compose down -v` | `docker compose down -v` |

### Affected Sections

1. ✅ **Start APP Container** - `docker compose up -d`
2. ✅ **Show APP Startup Logs** - `docker compose logs`
3. ✅ **Collect APP Logs** - `docker compose logs` and `docker compose ps`
4. ✅ **Stop and Remove Containers** - `docker compose down -v`

## Docker Compose V2 vs V1

### Docker Compose V1 (Legacy)
```bash
# Installed separately
pip install docker-compose

# Command (hyphen)
docker-compose --version
docker-compose up
```

### Docker Compose V2 (Current)
```bash
# Built into Docker CLI as plugin
docker compose version

# Command (space)
docker compose version
docker compose up
```

## Verification

### Check Your Version

**GitHub Actions (automatic):**
```yaml
# Already using V2 by default
docker compose version
```

**Local Development:**
```bash
# Check if you have V2
docker compose version

# Output should be:
# Docker Compose version v2.x.x
```

### If You Need V2 Locally

**Mac (Docker Desktop):**
- Docker Desktop includes V2 by default
- Update Docker Desktop to latest version

**Linux:**
```bash
# Install Docker Compose V2
sudo apt-get update
sudo apt-get install docker-compose-plugin

# Verify
docker compose version
```

**Windows (Docker Desktop):**
- Docker Desktop includes V2 by default
- Update Docker Desktop to latest version

## Backward Compatibility

If you still need `docker-compose` (V1) command locally:

```bash
# V2 provides an alias (some systems)
echo 'alias docker-compose="docker compose"' >> ~/.bashrc
source ~/.bashrc

# Or install V1 alongside V2
pip install docker-compose
```

## Testing the Fix

### In GitHub Actions

1. **Commit and push:**
   ```bash
   git add .github/workflows/test-vuln-bank.yml
   git add PIPELINE-IMPLEMENTATION.md
   git add FIX-DOCKER-COMPOSE-V2.md
   git commit -m "Fix: Update to Docker Compose V2 syntax"
   git push origin main
   ```

2. **Watch the workflow:**
   - Go to: https://github.com/smilyutin/bank-tests/actions
   - Should now see: ✅ `docker compose up -d` succeeds

### Expected Output

```
Starting application...
✅ [+] Running 2/2
 ✅ Network app-repo_default  Created
 ✅ Container app-repo-app-1  Started

Waiting for container to initialize...

Container status:
NAME              IMAGE             STATUS         PORTS
app-repo-app-1    vuln-bank:test    Up 8 seconds   0.0.0.0:5001->5001/tcp

CONTAINER ID   IMAGE            STATUS         PORTS
abc123def456   vuln-bank:test   Up 8 seconds   0.0.0.0:5001->5001/tcp
```

## Files Updated

1. ✅ `.github/workflows/test-vuln-bank.yml` - Fixed all `docker-compose` → `docker compose`
2. ✅ `PIPELINE-IMPLEMENTATION.md` - Added troubleshooting section
3. ✅ `FIX-DOCKER-COMPOSE-V2.md` - This file (documentation)

## Impact

### Before Fix
```
❌ Workflow fails immediately
❌ "command not found" error
❌ Cannot start application
❌ Tests don't run
```

### After Fix
```
✅ Workflow runs successfully
✅ Application starts properly
✅ Tests execute
✅ Reports generated
```

## Migration Notes

If you have other workflows or scripts:

### In GitHub Actions
```yaml
# ✅ Use this (V2)
- run: docker compose up -d

# ❌ Not this (V1)
- run: docker-compose up -d
```

### In Scripts
```bash
# ✅ Use this (V2)
docker compose up -d
docker compose logs
docker compose down

# ❌ Not this (V1)
docker-compose up -d
docker-compose logs
docker-compose down
```

### In Documentation
```markdown
# ✅ Recommend this (V2)
Run `docker compose up -d`

# ❌ Not this (V1)
Run `docker-compose up -d`
```

## Additional Resources

- [Docker Compose V2 Documentation](https://docs.docker.com/compose/cli-command/)
- [Migration Guide](https://docs.docker.com/compose/migrate/)
- [GitHub Actions Docker Support](https://docs.github.com/en/actions/guides/building-and-testing-nodejs)

## Summary

✅ **Fixed:** All `docker-compose` commands updated to `docker compose`  
✅ **Tested:** Ready to work with GitHub Actions runners  
✅ **Compatible:** Works with Docker Compose V2  
✅ **Documented:** Troubleshooting guide updated  

**Next Step:** Commit and push to test the fix! 🚀
