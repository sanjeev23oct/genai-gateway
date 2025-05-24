# 🚀 Deploy LLM Gateway to Railway

## Quick Deploy (5 minutes)

### **Step 1: Prepare Repository**

1. **Initialize Git** (if not already done):
```bash
git init
git add .
git commit -m "Initial LLM Gateway commit"
```

2. **Push to GitHub**:
```bash
# Create new repo on GitHub, then:
git remote add origin https://github.com/yourusername/genai-gateway.git
git branch -M main
git push -u origin main
```

### **Step 2: Deploy to Railway**

1. **Go to Railway**: https://railway.app
2. **Sign up/Login** with GitHub
3. **Click "New Project"**
4. **Select "Deploy from GitHub repo"**
5. **Choose your `genai-gateway` repository**
6. **Railway will auto-deploy!** ✨

### **Step 3: Configure Environment Variables**

In Railway dashboard:

1. **Go to your project**
2. **Click "Variables" tab**
3. **Add these variables**:

```bash
DEEPSEEK_API_KEY=your_deepseek_api_key_here
BLOCK_ON_DETECTION=true
PORT=8000
```

### **Step 4: Test Your Gateway**

1. **Get your Railway URL** (e.g., `https://your-app.railway.app`)
2. **Test health endpoint**:
```bash
curl https://your-app.railway.app/health
```

3. **Test chat endpoint**:
```bash
curl -X POST https://your-app.railway.app/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

4. **Test security blocking**:
```bash
curl -X POST https://your-app.railway.app/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "My email is test@example.com"}]
  }'
```

## 🎉 That's It!

Your LLM Gateway is now live on Railway!

## 📊 Railway Features You Get

- ✅ **Auto-scaling**: Handles traffic spikes
- ✅ **HTTPS**: Automatic SSL certificates
- ✅ **Monitoring**: Built-in metrics and logs
- ✅ **Custom Domain**: Add your own domain
- ✅ **Environment Management**: Easy config updates
- ✅ **Git Integration**: Auto-deploy on push

## 🔧 Configuration Options

### **Environment Variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `DEEPSEEK_API_KEY` | Your DeepSeek API key | Required for real responses |
| `BLOCK_ON_DETECTION` | Block requests with security issues | `true` |
| `PORT` | Server port | `8000` |
| `DEEPSEEK_BASE_URL` | DeepSeek API base URL | `https://api.deepseek.com` |

### **Railway Settings:**

- **Health Check**: `/health` endpoint
- **Auto-restart**: On failure
- **Build**: Automatic with Nixpacks
- **Runtime**: Python 3.11

## 🧪 Testing Your Deployment

### **1. Health Check**
```bash
curl https://your-app.railway.app/health
```
**Expected**: `{"status": "healthy", ...}`

### **2. Normal Request**
```bash
curl -X POST https://your-app.railway.app/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "deepseek-chat", "messages": [{"role": "user", "content": "Hello!"}]}'
```
**Expected**: Chat response from DeepSeek (or mock response)

### **3. Security Block Test**
```bash
curl -X POST https://your-app.railway.app/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model": "deepseek-chat", "messages": [{"role": "user", "content": "My API key is sk-1234567890abcdef"}]}'
```
**Expected**: `400 Bad Request` with security violation message

## 📱 Web Interface

Visit your Railway URL in a browser to see:
- ✅ Gateway status
- ✅ Security features overview
- ✅ API documentation
- ✅ Test commands

## 🔍 Monitoring & Logs

In Railway dashboard:
- **Metrics**: View request counts, response times
- **Logs**: See real-time application logs
- **Deployments**: Track deployment history

## 🚀 Next Steps

1. **Share URL with team**: Use the Railway URL as your LLM endpoint
2. **Configure coding agents**: Point them to your gateway
3. **Monitor usage**: Check Railway dashboard for metrics
4. **Add custom domain**: Optional, for branded URLs

## 💰 Pricing

Railway offers:
- **Free tier**: $5 credit monthly
- **Pro plan**: $20/month for production use
- **Pay-as-you-go**: Based on usage

Your gateway should easily fit in the free tier for MVP testing!

## 🆘 Troubleshooting

### **Deployment Issues:**
- Check Railway build logs
- Ensure all files are committed to Git
- Verify `railway_main.py` is in root directory

### **Runtime Issues:**
- Check Railway application logs
- Verify environment variables are set
- Test health endpoint first

### **API Issues:**
- Verify DeepSeek API key is correct
- Check request format matches examples
- Monitor Railway logs for errors

## 🎯 Success!

Your LLM Gateway is now:
- ✅ **Live on Railway**
- ✅ **Securing your team's LLM requests**
- ✅ **Blocking PII and secrets**
- ✅ **Ready for production use**

Share the Railway URL with your development team and start using it with their coding agents!
