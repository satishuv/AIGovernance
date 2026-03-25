@echo off
"%~dp0.venv\Scripts\python.exe" "%~dp0_verify_synth.py"
echo EXIT_CODE=%ERRORLEVEL%
