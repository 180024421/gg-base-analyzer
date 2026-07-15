@echo off
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
  call .venv\Scripts\pip install -e ".[dev]"
)
call .venv\Scripts\python -m gg_base_analyzer gui
