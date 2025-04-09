# Use the Microsoft Windows Server 2019 image as base
FROM mcr.microsoft.com/windows/servercore:ltsc2019

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
RUN cmd /S /C "pip install --upgrade pip && pip install pyarrow snowflake-connector-python"
    # pip install pyarrow=1.19.0 snowflake-connector-python=3.12.4

# Create application directory
RUN powershell -Command "New-Item -Path 'C:\\myapp' -ItemType Directory -Force"

# Copy application files
COPY . C:\myapp

# Set the working directory
WORKDIR C:\myapp

# Run the Python application
CMD ["python", "pyarrow-hw.py"]
