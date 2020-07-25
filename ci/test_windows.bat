::
:: Test PythonConnector on Windows
::

@echo off

SET SCRIPT_DIR=%~dp0
SET CONNECTOR_DIR=%~dp0\..\
set pv=%1

:: first download wheel file from s3 bucket
cd %workspace%
cmd /c aws s3 cp s3://sfc-jenkins/repository/python_connector/win64/%GIT_BRANCH%/%GIT_COMMIT% %workspace% ^
    --recursive --only-show-errors ^
    --include "*.whl"

dir /b * | findstr ^snowflake_connector_python.*%pv%.*whl$ > whl_name
if %errorlevel% neq 0 goto :error

set /p connector_whl=<whl_name
if "%connector_whl%"=="" (
    echo "[Error] Python connector wheel file not found"
    exit /b 1
)
echo %connector_whl%

:: create tox execution virtual env
set venv_dir=%WORKSPACE%\tox_venv
py -3.6 -m venv %venv_dir%
if %errorlevel% neq 0 goto :error

call %venv_dir%\scripts\activate
if %errorlevel% neq 0 goto :error

python -m pip install -U pip tox tox-external-wheels
if %errorlevel% neq 0 goto :error

cd %CONNECTOR_DIR%

set JUNIT_REPORT_DIR=%workspace%
set COV_REPORT_DIR=%workspace%
tox -e py%pv%-ci,py%pv%-pandas-ci,py%pv%-sso-ci --external_wheels ..\..\..\%connector_whl% -- --basetemp=%workspace%\pytest-tmp\
if %errorlevel% neq 0 goto :error

call deactivate
EXIT /B 0

:error
exit /b %errorlevel%
