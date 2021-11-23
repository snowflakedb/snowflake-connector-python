::
:: Test PythonConnector on Windows
::


SET SCRIPT_DIR=%~dp0
SET CONNECTOR_DIR=%~dp0\..\
:: E.g.: 35
set pv=%1

cd %CONNECTOR_DIR%

dir /b * | findstr ^snowflake_connector_python.*%pv%.*whl$ > whl_name
if %errorlevel% neq 0 goto :error

set /p connector_whl=<whl_name
if "%connector_whl%"=="" (
    echo "[Error] Python connector wheel file not found"
    exit /b 1
)
echo %connector_whl%

:: Decrypt parameters file
:: Default to aws as cloud provider
set PARAMETERS_DIR=%CONNECTOR_DIR%\.github\workflows\parameters\public
set PARAMS_FILE=%PARAMETERS_DIR%\parameters_aws.py.gpg
if "%cloud_provider%"=="azure" set PARAMS_FILE=%PARAMETERS_DIR%\parameters_azure.py.gpg
if "%cloud_provider%"=="gcp" set PARAMS_FILE=%PARAMETERS_DIR%\parameters_gcp.py.gpg
gpg --quiet --batch --yes --decrypt --passphrase="%PARAMETERS_SECRET%" %PARAMS_FILE% > test\parameters.py

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
tox -e py%pv%-{unit,integ,pandas,sso}-ci --external_wheels %connector_whl% -- --basetemp=%workspace%\pytest-tmp\
if %errorlevel% neq 0 goto :error

call deactivate
EXIT /B 0

:error
exit /b %errorlevel%
