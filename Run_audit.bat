@echo off
rem Runs NetAudit on the local subnet. Any arguments are passed on to the program.
rem For scheduled runs call "python -m netaudit ..." directly instead of this file (see README).
setlocal
pushd "%~dp0"

rem Try each interpreter by running it: a "python" found on PATH may be the Microsoft Store stub.
set "PY=python"
%PY% -c "import sys; sys.exit(sys.version_info < (3, 9))" >nul 2>nul && goto run
set "PY=py -3"
%PY% -c "import sys; sys.exit(sys.version_info < (3, 9))" >nul 2>nul && goto run

echo NetAudit needs Python 3.9 or later, and none was found.
echo Install it with:   winget install Python.Python.3.12
echo or from https://www.python.org/downloads/ (tick "Add python.exe to PATH" during setup).
echo.
pause
popd
exit /b 2

:run
%PY% -m netaudit %*
set "CODE=%ERRORLEVEL%"
popd
rem Keep the window open only when it was opened by a double-click (no arguments).
if "%~1"=="" (
  echo.
  pause
)
exit /b %CODE%
