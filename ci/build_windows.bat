::
:: Build Snowflake Python Connector on Windows
:: NOTES:
::   - This is designed to ONLY be called in our Windows workers in Jenkins
::   - To restrict what version gets created edit this file
SET SCRIPT_DIR=%~dp0
SET CONNECTOR_DIR=%~dp0\..\

set python_versions= 3.9 3.10 3.11 3.12 3.13

cd %CONNECTOR_DIR%

set venv_dir=%WORKSPACE%\venv-flake8
if %errorlevel% neq 0 goto :error

py -3.9 -m venv %venv_dir%
if %errorlevel% neq 0 goto :error

call %venv_dir%\scripts\activate
if %errorlevel% neq 0 goto :error

python -m pip install --upgrade pip awscli setuptools wheel
if %errorlevel% neq 0 goto :error

(for %%v in (%python_versions%) do (
   call :build_wheel_file %%v || goto :error
))

call deactivate

dir dist

EXIT /B %ERRORLEVEL%

:build_wheel_file
set pv=%~1

echo Going to compile wheel for Python %pv%
py -%pv% -m pip install --upgrade pip setuptools wheel build delvewheel
if %errorlevel% neq 0 goto :error

py -%pv% -m build --outdir dist\rawwheel --wheel .
if %errorlevel% neq 0 goto :error

:: patch the wheel by including its dependencies
py -%pv% -m delvewheel repair -vv -w dist dist\rawwheel\*
if %errorlevel% neq 0 goto :error

rd /s /q dist\rawwheel

EXIT /B 0

:error
exit /b %errorlevel%
