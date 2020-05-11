nuget install secure-file -ExcludeVersion
secure-file\tools\secure-file -decrypt parameters.appveyor.py.enc -secret %my_secret% -out parameters.py
copy parameters.py test

SET SCRIPT_DIR=%~dp0

"%PYTHON%/python.exe" -m venv env
call env\Scripts\activate
# https://github.com/pypa/pip/issues/6566
python -m pip install --upgrade pip
:: These versions have to be kept in sync with what is pinned in setup.py manually
pip install "pyarrow==0.17.0"
pip install wheel
pip install Cython
set ENABLE_EXT_MODULES=true
python setup.py bdist_wheel -d dist

:: figure out connector wheel file name
cd dist
dir /b * > whl_name
set /p connector_whl=<whl_name
pip install %connector_whl%[pandas,development]
pip list --format=columns

cd %SCRIPT_DIR%/..
