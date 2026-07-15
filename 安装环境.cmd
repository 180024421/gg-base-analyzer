@echo off
cd /d "%~dp0"
python -m venv .venv
call .venv\Scripts\pip install -U pip
call .venv\Scripts\pip install -e ".[dev]"
echo.
echo 可选在线功能: .venv\Scripts\pip install -e ".[online]"
echo 完成. 运行 一键启动.cmd
pause
