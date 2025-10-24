# 🎯 Pipeline Implementation - Complete Guide

## Overview

**Strategy:** Test repo clones APP repo, builds it, tests it, and destroys it.

**Your Repositories:**
- **Test Repo:** https://github.com/smilyutin/bank-tests (this repo)
- **APP Repo:** https://github.com/smilyutin/vuln_bank

**Key Benefit:** No changes needed in APP repo! Everything managed from Test repo.

---

## 📁 What Was Created

### Files Added to Test Repo

```
bank-tests/
└── .github/workflows/
    ├── test-vuln-bank.yml              ✅ CREATED - Main workflow
    └── scheduled-security-tests.yml    ✅ CREATED - Scheduled tests
```

### Files Already Configured

```
bank-tests/
├── playwright.config.ts                ✅ Already has BASE_URL support
└── package.json                        ✅ Already has test scripts
```

---

## 🔄 How It Works

### Workflow Execution Flow

```
1. 🎬 Trigger (push/PR/manual/schedule)
        ↓
2. 📥 Clone Test Repo (smilyutin/bank-tests)
        ↓
3. 📦 Install Test Dependencies
        ↓
4. 📥 Clone APP Repo (smilyutin/vuln_bank)
        ↓
5. 📦 Install APP Dependencies
        ↓
6. 🐳 Create Dockerfile & docker-compose.yml (if missing)
        ↓
7. 🔨 Build APP Docker Image
        ↓
8. 🚀 Start APP Container (docker-compose up)
        ↓
9. ⏳ Wait for Health Check
        ↓
10. 🧪 Run Tests (API + Security + UI)
        ↓
11. 📊 Generate Reports (Playwright + Allure)
        ↓
12. 📤 Upload Artifacts
        ↓
13. 🧹 Cleanup (docker-compose down)
        ↓
14. ✅ Done!
```

---

## 🚀 Testing the Setup

### Test 1: Manual Trigger (Recommended First Test)

1. **Go to GitHub:**
   - Visit: https://github.com/smilyutin/bank-tests
   - Click: **Actions** tab
   - Click: **Test Vulnerable Bank Application** workflow
   - Click: **Run workflow** button

2. **Configure Run:**
   - **Branch:** `main` (use test repo branch)
   - **APP branch:** `main` (vuln_bank branch)
   - **Soft mode:** `true` (recommended for first test)
   - **Test suite:** `all`

3. **Start:**
   - Click: **Run workflow**

4. **Watch:**
   - Workflow starts immediately
   - Click on the running workflow to see live logs
   - Should complete in ~10-15 minutes

5. **Expected Result:**
   ```
   ✅ Clone repos: Success
   ✅ Build APP: Success
   ✅ Start APP: Success
   ✅ Wait for health: Success
   ✅ Run tests: Complete (may have warnings in SOFT mode)
   ✅ Generate reports: Success
   ✅ Cleanup: Success
   ```

---

### Test 2: Automatic Trigger (Push to Test Repo)

1. **Make a change in Test repo:**
   ```bash
   cd /Users/minime/Projects/bank-tests
   
   # Make any change to tests
   echo "// Test trigger" >> tests/security/README.md
   
   git add .
   git commit -m "Test: Trigger CI workflow"
   git push origin main
   ```

2. **Check GitHub Actions:**
   - Go to: https://github.com/smilyutin/bank-tests/actions
   - Should see new workflow run starting automatically

3. **Expected Result:**
   - Workflow triggers within seconds
   - Runs same steps as manual trigger
   - Completes successfully

---

### Test 3: Test with Different APP Branch

1. **Trigger workflow with develop branch:**
   - Actions → Test Vulnerable Bank Application
   - Run workflow
   - Set **APP branch:** `develop` (if exists)
   - Run

2. **Workflow will:**
   - Clone develop branch of vuln_bank
   - Build and test that version
   - Report results

---

## 📊 Understanding Workflow Outputs

### Live Logs

Click on any step to see real-time output:

```
📥 Clone APP Repo
  ✅ Cloning into 'app-repo'...
  ✅ Checking out branch 'main'...

🔨 Build APP Docker Image
  ✅ Building Docker image...
  ✅ Step 1/6 : FROM node:20-alpine
  ✅ Step 2/6 : WORKDIR /app
  ...

🚀 Start APP Container
  ✅ Creating network...
  ✅ Creating volume...
  ✅ Starting container...

⏳ Wait for APP to be Ready
  ⏳ Waiting for app... (09:15:30)
  ⏳ Waiting for app... (09:15:33)
  ✅ Application is ready!

🧪 Run Tests
  Running API tests...
  ✅ 45 passed
  
  Running Security tests...
  ⚠️  18 warnings (SOFT mode)
  ✅ 52 passed
```

### Artifacts Available

After workflow completes, scroll to bottom:

```
📦 Artifacts (4)
├── playwright-report-123      Download HTML test report
├── allure-report-123          Download Allure report  
├── test-results-123           Download JSON results
└── app-logs-123               Download application logs
```

Click any artifact to download and view locally.

---

## 🎯 SOFT Mode vs HARD Mode

### SOFT Mode (Default) ✅ Recommended

```yaml
soft_mode: 'true'
```

**Behavior:**
- Tests run completely
- Security issues logged as **warnings**
- Workflow **does not fail**
- Reports generated with all findings

**Use When:**
- Developing new tests
- Running on PRs
- Daily automated runs
- Gathering security metrics

**Example Output:**
```
⚠️  18 security findings detected
✅ Tests completed (SOFT mode - not failing build)
```

### HARD Mode

```yaml
soft_mode: 'false'
```

**Behavior:**
- Tests run completely
- Security issues cause **test failures**
- Workflow **fails** if issues found
- Blocks deployment/release

**Use When:**
- Release validation
- Production deployment gates
- Compliance requirements
- Nightly security scans

**Example Output:**
```
❌ 18 security issues found
❌ Tests failed (HARD mode - failing build)
```

---

## 🔧 Customization Options

### Change Default Branch

Edit `.github/workflows/test-vuln-bank.yml`:

```yaml
env:
  APP_BRANCH: ${{ inputs.app_branch || 'develop' }}  # Change from 'main'
```

### Change Default Port

If your app uses different port:

```yaml
env:
  BASE_URL: 'http://localhost:3000'  # Change from 5001
```

And update in docker-compose creation:

```yaml
ports:
  - "3000:3000"  # Change from 5001:5001
```

### Add More Test Suites

Edit workflow `test_suite` input:

```yaml
test_suite:
  type: choice
  options:
    - 'all'
    - 'api'
    - 'security'
    - 'ui'
    - 'performance'  # Add new
```

Then add case in Run Tests step:

```yaml
performance)
  echo "🚀 Running Performance tests..."
  npm run test:perf || EXIT_CODE=$?
  ;;
```

### Adjust Timeouts

If app takes longer to start:

```yaml
- name: ⏳ Wait for APP to be Ready
  run: |
    timeout 300 bash -c '  # Increase from 120 to 300
      until curl -f http://localhost:5001/health; do
        sleep 5  # Increase from 3 to 5
      done
    '
```

---

## 🐛 Troubleshooting

### Issue: "APP Repo not found"

**Cause:** Repo is private and GITHUB_TOKEN doesn't have access

**Fix:** Create Personal Access Token (PAT)

1. Go to: https://github.com/settings/tokens
2. Generate new token (classic)
3. Scopes: `repo` (all)
4. Copy token
5. Add to secrets:
   - Go to: https://github.com/smilyutin/bank-tests/settings/secrets/actions
   - New repository secret
   - Name: `APP_REPO_TOKEN`
   - Value: (paste token)
6. Update workflow line 63:
   ```yaml
   token: ${{ secrets.APP_REPO_TOKEN }}  # Change from GITHUB_TOKEN
   ```

### Issue: "Health check timeout"

**Symptoms:**
```
⏳ Waiting for app... (timeout)
❌ Error: Application failed to start
```

**Fixes:**

1. **Check logs:**
   - Click on "Show APP Startup Logs" step
   - Look for errors

2. **Verify port:**
   - APP might use different port
   - Check APP repo package.json for port

3. **Add fallback health check:**
   ```yaml
   curl -f http://localhost:5001/health || curl -f http://localhost:5001/
   ```

4. **Increase timeout:**
   ```yaml
   timeout 300  # Increase from 120
   ```

### Issue: "Docker build failed"

**Symptoms:**
```
❌ Error: failed to solve with frontend dockerfile.v0
```

**Fixes:**

1. **Check APP repo has valid code:**
   - package.json exists
   - npm install works locally

2. **Check Docker logs:**
   - View "Build APP Docker Image" step logs
   - Look for missing dependencies

3. **Test locally:**
   ```bash
   cd ../vuln_bank
   docker build -t test .
   ```

### Issue: "Tests can't connect to APP"

**Symptoms:**
```
❌ Error: connect ECONNREFUSED 127.0.0.1:5001
```

**Fixes:**

1. **Verify APP is running:**
   ```yaml
   docker ps  # Check container status
   ```

2. **Check port mapping:**
   ```yaml
   ports:
     - "5001:5001"  # HOST:CONTAINER
   ```

3. **Test connection:**
   ```bash
   curl -v http://localhost:5001/
   ```

### Issue: "Cleanup didn't remove containers"

**Symptoms:**
```
⚠️  Containers still running after cleanup
```

**Fix:** Add force cleanup:

```yaml
- name: 🧹 Force Cleanup
  if: always()
  run: |
    docker stop $(docker ps -aq) || true
    docker rm $(docker ps -aq) || true
    docker system prune -af
```

---

## 📈 Performance Optimization

### Speed Up Builds

1. **Cache Docker layers:**
   ```yaml
   - name: Set up Docker Buildx
     uses: docker/setup-buildx-action@v3
   
   - name: Cache Docker layers
     uses: actions/cache@v3
     with:
       path: /tmp/.buildx-cache
       key: ${{ runner.os }}-buildx-${{ github.sha }}
   ```

2. **Cache npm dependencies:**
   ```yaml
   - name: Cache node modules
     uses: actions/cache@v3
     with:
       path: |
         test-repo/node_modules
         app-repo/node_modules
       key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
   ```

3. **Parallel test execution:**
   ```yaml
   strategy:
     matrix:
       shard: [1, 2, 3, 4]
   run: npx playwright test --shard=${{ matrix.shard }}/4
   ```

### Reduce Test Time

1. **Run smoke tests on PR:**
   ```yaml
   - name: Quick Smoke Test
     if: github.event_name == 'pull_request'
     run: npm run test:smoke
   ```

2. **Full suite only on main:**
   ```yaml
   - name: Full Test Suite
     if: github.ref == 'refs/heads/main'
     run: npm run test:sec
   ```

---

## 📊 Monitoring

### Check Workflow Status

```bash
# Install GitHub CLI
brew install gh

# List recent runs
gh run list --repo smilyutin/bank-tests

# Watch live run
gh run watch --repo smilyutin/bank-tests

# View specific run
gh run view <run-id> --log
```

### Download Artifacts

```bash
# List artifacts
gh run view <run-id>

# Download all artifacts
gh run download <run-id>

# Download specific artifact
gh run download <run-id> --name playwright-report-123
```

### Set Up Notifications

Add to workflow (after tests):

```yaml
- name: Send Slack Notification
  if: always()
  env:
    SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
  run: |
    curl -X POST $SLACK_WEBHOOK \
      -H 'Content-Type: application/json' \
      -d '{
        "text": "Test Results: ${{ job.status }}",
        "blocks": [{
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*Tests:* ${{ job.status }}\n*Branch:* ${{ env.APP_BRANCH }}\n*Link:* ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
          }
        }]
      }'
```

---

## ✅ Verification Checklist

- [ ] Workflows created in `.github/workflows/`
- [ ] playwright.config.ts has BASE_URL support
- [ ] package.json has test scripts
- [ ] Manual trigger works
- [ ] Automatic trigger works (push to test repo)
- [ ] APP builds successfully
- [ ] APP starts and responds
- [ ] Tests run and complete
- [ ] Reports generated
- [ ] Artifacts uploadable
- [ ] Cleanup removes containers
- [ ] Logs available for debugging

---

## 🎓 Next Steps

### Immediate (After Setup)
1. ✅ Test manual trigger
2. ✅ Test automatic trigger
3. ✅ Download and review reports
4. ✅ Verify cleanup works

### Short Term (1 week)
1. Add more test coverage
2. Configure scheduled tests
3. Set up notifications
4. Optimize performance

### Long Term (1 month)
1. Add parallel test execution
2. Implement test result trends
3. Create custom dashboards
4. Add deployment gates

---

## 📞 Support

- **Workflow file:** `.github/workflows/test-vuln-bank.yml`
- **Logs:** GitHub Actions → Click workflow run
- **Artifacts:** Bottom of workflow run page
- **Test reports:** Download playwright-report artifact

---

## 🎉 Summary

**What You Have:**
- ✅ Automated testing on every push
- ✅ Manual trigger with options
- ✅ Scheduled nightly tests
- ✅ SOFT mode by default (non-blocking)
- ✅ Complete test reports
- ✅ Automatic cleanup
- ✅ No APP repo changes needed!

**Ready to test:** Go to Actions tab and click "Run workflow"! 🚀
