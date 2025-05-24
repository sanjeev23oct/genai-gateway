@echo off
echo 🚀 Pushing LLM Gateway to GitHub
echo =====================================

echo.
echo 1. Initializing Git repository...
git init

echo.
echo 2. Adding remote repository...
git remote add origin https://github.com/sanjeev23oct/genai-gateway.git

echo.
echo 3. Adding all files...
git add .

echo.
echo 4. Creating initial commit...
git commit -m "Initial LLM Gateway MVP - Railway ready deployment

Features:
✅ PII Detection (emails, phones, SSNs, credit cards)
✅ Secret Detection (API keys, passwords, tokens)
✅ DeepSeek Integration
✅ Security Blocking
✅ Audit Logging
✅ Railway Deployment Ready
✅ Docker Support
✅ Health Monitoring
✅ CORS Support

Files:
- railway_main.py: Railway-optimized gateway
- app/: Full FastAPI implementation
- cloud_gateway.py: Cloud-ready version
- Dockerfile: Container configuration
- requirements.txt: Dependencies
- RAILWAY_DEPLOY.md: Deployment guide"

echo.
echo 5. Setting main branch...
git branch -M main

echo.
echo 6. Pushing to GitHub...
git push -u origin main

echo.
echo =====================================
echo ✅ Successfully pushed to GitHub!
echo.
echo Repository: https://github.com/sanjeev23oct/genai-gateway
echo.
echo Next steps:
echo 1. Go to https://railway.app
echo 2. Login with GitHub
echo 3. Click "New Project"
echo 4. Select "Deploy from GitHub repo"
echo 5. Choose "sanjeev23oct/genai-gateway"
echo 6. Add environment variables in Railway
echo =====================================

pause
