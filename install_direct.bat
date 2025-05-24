@echo off
echo 🔧 Direct Installation (No Virtual Environment)
echo ===============================================

echo.
echo Attempting to install packages directly...
echo.

echo 1. Trying with py launcher...
py -3.13 -m pip install fastapi uvicorn httpx python-dotenv structlog
if %errorlevel% neq 0 (
    echo ❌ py launcher failed, trying alternative...
    goto :try_alternative
)

echo 2. Installing additional packages...
py -3.13 -m pip install presidio-analyzer presidio-anonymizer spacy python-multipart
if %errorlevel% neq 0 (
    echo ⚠️ Some packages failed, continuing...
)

echo 3. Downloading spaCy model...
py -3.13 -m spacy download en_core_web_sm
if %errorlevel% neq 0 (
    echo ⚠️ spaCy model download failed, will use basic detection
)

goto :test_installation

:try_alternative
echo.
echo Trying with full Python path...
C:\Users\DELL\AppData\Local\Programs\Python\Python313\python.exe -m pip install fastapi uvicorn httpx python-dotenv structlog
if %errorlevel% neq 0 (
    echo ❌ Direct installation also failed
    echo.
    echo 💡 Recommendations:
    echo 1. Reinstall Python 3.13 from python.org
    echo 2. Install Miniconda instead
    echo 3. Use Docker
    goto :end
)

:test_installation
echo.
echo 4. Testing installation...
py -3.13 -c "import sys; print(f'Python: {sys.version}'); import fastapi; print('✅ FastAPI works')"

echo.
echo ===============================================
echo ✅ Installation attempt complete!
echo.
echo To run the gateway:
echo   py -3.13 -m app.main
echo.
echo To test:
echo   py -3.13 test_gateway.py
echo ===============================================

:end
pause
