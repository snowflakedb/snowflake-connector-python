nuget install secure-file -ExcludeVersion
secure-file\tools\secure-file -decrypt parameters.appveyor.py.enc -secret %my_secret% -out parameters.py
copy parameters.py test

"%PYTHON%/python.exe" -m venv env
call env\Scripts\activate
python -m pip install --upgrade pip
pip install numpy
pip install pytest pytest-cov pytest-rerunfailures
pip install .
pip install .[azure]
pip list --format=columns
