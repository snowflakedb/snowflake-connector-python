nuget install secure-file -ExcludeVersion
secure-file\tools\secure-file -decrypt parameters.appveyor.py.enc -secret %my_secret% -out parameters.py
copy parameters.py test

"%PYTHON%/python.exe" -m venv env
call env\Scripts\activate
# https://github.com/pypa/pip/issues/6566
python -m pip install --upgrade pip==18.1
pip install pendulum
pip install numpy
pip install pytest pytest-cov pytest-rerunfailures
pip install .[aws,azure]
pip list --format=columns
