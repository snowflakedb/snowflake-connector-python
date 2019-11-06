nuget install secure-file -ExcludeVersion
secure-file\tools\secure-file -decrypt parameters.appveyor.py.enc -secret %my_secret% -out parameters.py
copy parameters.py test

SET SCRIPT_DIR=%~dp0

"%PYTHON%/python.exe" -m venv env
call env\Scripts\activate
# https://github.com/pypa/pip/issues/6566
python -m pip install --upgrade pip
pip install pandas
pip install numpy
pip install pendulum
pip install pyarrow
pip install pytest pytest-cov pytest-rerunfailures
pip install wheel
pip install Cython
set ENABLE_EXT_MODULES=true
python setup.py bdist_wheel -d dist

:: figure out connector wheel file name
cd dist
dir /b * > whl_name
set /p connector_whl=<whl_name
pip install %connector_whl%
pip list --format=columns

cd %SCRIPT_DIR%/..
