@echo off
echo 🚀 Setting up LLM Gateway Environment
echo =====================================

echo.
echo 1. Creating virtual environment...
C:\Users\DELL\AppData\Local\Programs\Python\Python313\python.exe -m venv gateway_env

echo.
echo 2. Activating virtual environment...
call gateway_env\Scripts\activate.bat

echo.
echo 3. Upgrading pip...
python -m pip install --upgrade pip

echo.
echo 4. Installing dependencies...
pip install -r requirements.txt

echo.
echo 5. Downloading spaCy model...
python -m spacy download en_core_web_sm

echo.
echo 6. Testing installation...
python -c "import fastapi, uvicorn, presidio_analyzer; print('✅ All packages installed successfully')"

echo.
echo =====================================
echo ✅ Environment setup complete!
echo.
echo To activate the environment in future:
echo   gateway_env\Scripts\activate
echo.
echo To run the gateway:
echo   python -m app.main
echo.
echo To test the gateway:
echo   python test_gateway.py
echo =====================================

pause
