# Use the Microsoft Windows Server 2019 image as base
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Install the Microsoft Visual C++ Redistributable 2015–2022
RUN powershell -Command " \
  Invoke-WebRequest -Uri https://aka.ms/vs/17/release/vc_redist.x64.exe -OutFile C:\\vc_redist.x64.exe; \
  Start-Process -Wait -FilePath C:\\vc_redist.x64.exe -ArgumentList '/install', '/quiet', '/norestart'; \
  Remove-Item C:\\vc_redist.x64.exe -Force \
"

# Download and install Python
RUN powershell -Command " \
    $ErrorActionPreference = 'Stop'; \
    Set-ExecutionPolicy Bypass -Scope Process -Force; \
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
    Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.10.11/python-3.10.11-amd64.exe' -OutFile 'C:\\python-installer.exe'; \
    Start-Process -Wait -FilePath 'C:\\python-installer.exe' -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0'; \
    Remove-Item 'C:\\python-installer.exe' -Force \
"

# Upgrade pip and install required Python packages
RUN cmd /S /C "python -m pip install --upgrade pip"
RUN cmd /S /C "pip install pyarrow snowflake-connector-python"
    # pip install pyarrow=1.19.0 snowflake-connector-python=3.12.4

# Create application directory
RUN powershell -Command "New-Item -Path 'C:\\myapp' -ItemType Directory -Force"

# Create and switch to application directory
WORKDIR /myapp

# Copy local files into the container
COPY . .

# Run the Python app
CMD ["python", "pyarrow-hw.py"]
