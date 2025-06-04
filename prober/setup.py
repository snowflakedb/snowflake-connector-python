from setuptools import find_packages, setup

setup(
    name="snowflake_prober",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "snowflake-connector-python",
        "requests",
        "faker"
    ],
    entry_points={
        "console_scripts": [
            "prober=probes.main:main",
        ],
    },
)
