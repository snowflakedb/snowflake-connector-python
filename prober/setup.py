from setuptools import setup, find_packages

setup(
    name="snowflake_prober",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "snowflake-connector-python",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "prober=probes.main:main",
        ],
    },
)