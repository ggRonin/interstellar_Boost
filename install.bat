@echo off
chcp 65001 >nul
rem Установка на новом ПК: виртуальное окружение .venv + библиотеки из requirements.txt
cd /d "%~dp0"

python --version >nul 2>&1 || (echo [!] Python не найден: установите Python 3.10+ с python.org ^(галочка "Add to PATH"^) & pause & exit /b 1)
node --version >nul 2>&1 || echo [!] Node.js не найден: установите Node.js 22.13+ с nodejs.org ^(нужен для капчи^)

if not exist .venv python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt || (echo [!] Ошибка установки & pause & exit /b 1)

echo.
echo [*] Готово. Запуск: .venv\Scripts\python.exe Boost.py
pause
