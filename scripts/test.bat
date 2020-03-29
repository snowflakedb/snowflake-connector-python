::
:: Test PythonConnector on Windows
::

@echo off

SET SCRIPT_DIR=%~dp0
SET CONNECTOR_DIR=%~dp0\..\
set pv=%1

:: set PIP_INDEX_URL=https://nexus.int.snowflakecomputing.com/repository/pypi/simple

:: first download wheel file from s3 bucket
cd %workspace%
cmd /c aws s3 cp s3://sfc-jenkins/repository/python_connector/win64/%branch%/%svn_revision% %workspace% ^
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

:: update config file
set conf_file=%CONNECTOR_DIR%test\parameters.py
echo #!/usr/bin/env python > %conf_file%
echo CONNECTION_PARAMETERS = { >> %conf_file%
echo    'account': '%sf_account%', >> %conf_file%
echo    'user': '%sf_user%', >> %conf_file%
echo    'password': '%sf_password%', >> %conf_file%
echo    'schema': '%sf_schema%', >> %conf_file%
echo    'database': '%sf_database%', >> %conf_file%
echo    'protocol': 'https', >> %conf_file%
echo    'host': '%sf_host%', >> %conf_file%
echo    'port': '%sf_port%', >> %conf_file%
echo    'warehouse': '%sf_warehouse%', >> %conf_file%
echo } >> %conf_file%

:: create tox execution virtual env
set venv_dir=%WORKSPACE%\tox_env
py -3.6 -m venv %venv_dir%
if %errorlevel% neq 0 goto :error

call %venv_dir%\scripts\activate
if %errorlevel% neq 0 goto :error

python -m pip install --upgrade pip
if %errorlevel% neq 0 goto :error

pip install tox tox-external-wheels>=0.1.4
if %errorlevel% neq 0 goto :error

cd %CONNECTOR_DIR%
:: check code style
:: should be switched to fix_lint when ticket SNOW-133050 is closed
tox -e flake8
if %errorlevel% neq 0 goto :error

set JUNIT_REPORT_DIR=%workspace%
set COV_REPORT_DIR=%workspace%
tox -e py%pv%-ci,py%pv%-pandas-ci,py%pv%-sso-ci,coverage --external_wheels ..\..\..\%connector_whl% -- --basetemp=%workspace%\pytest-tmp\ test
if %errorlevel% neq 0 goto :error

call deactivate
EXIT /B 0

:error
exit /b %errorlevel%
