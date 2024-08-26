@echo off
pip install -r data\requirements.txt >nul 2>&1

echo Please wait while the program starts up...
echo.
python data\SBOM.py

pause
