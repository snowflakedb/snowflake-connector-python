::
:: Build PythonConnector on Windows
::

@echo off

SET SCRIPT_DIR=%~dp0
SET CONNECTOR_DIR=%~dp0\..\

:: set PIP_INDEX_URL=https://nexus.int.snowflakecomputing.com/repository/pypi/simple

set python_versions= 3.5 3.6 3.7 3.8

(for %%v in (%python_versions%) do (
   call :build_wheel_file %%v || goto :error
))
cd %CONNECTOR_DIR%

EXIT /B %ERRORLEVEL%

:build_wheel_file
set pv=%~1
set venv_dir=%WORKSPACE%\venv-build-python%pv%

py -%pv% -m venv %venv_dir%
if %errorlevel% neq 0 goto :error

call %venv_dir%\scripts\activate
if %errorlevel% neq 0 goto :error

python -m pip install --upgrade pip
if %errorlevel% neq 0 goto :error

pip install --upgrade setuptools wheel Cython pyarrow==0.17.0 numpy
if %errorlevel% neq 0 goto :error

cd %CONNECTOR_DIR%

set ENABLE_EXT_MODULES=true
python setup.py bdist_wheel
if %errorlevel% neq 0 goto :error

set ENABLE_EXT_MODULES=
call deactivate
EXIT /B 0

:error
exit /b %errorlevel%
