@echo off
rem run this once from the agent folder
rem login will start sentinel with pythonw
rem install_startup.bat off   removes it
set "HERE=%~dp0"
set "DEST=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sentinel.bat"
if /i "%~1"=="off" (
  del "%DEST%" 2>nul
  echo removed %DEST%
  goto : eof
)
> "%DEST%" echo @echo off
>> "%DEST%" echo cd /d "%HERE%"
>> "%DEST%" echo start "" pythonw main.py
echo wrote %DEST%
echo try it: double click that file. 