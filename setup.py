#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
from codecs import open
from os import path
import os

from setuptools import setup
from os.path import join

THIS_DIR = path.dirname(path.realpath(__file__))

try:
    from generated_version import VERSION
except:
    from version import VERSION
version = '.'.join([str(v) for v in VERSION if v is not None])

with open(path.join(THIS_DIR, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()

cython_build_dir = join("build", "cython")
cython_source = [
    "arrow_iterator.pyx"
]
enable_ext_modules = os.environ.get("ENABLE_EXT_MODULES", "false")
ext_modules = None
if enable_ext_modules == "true":
    from Cython.Build import cythonize
    ext_modules = cythonize(cython_source, build_dir=cython_build_dir)

setup(
    name='snowflake-connector-python',
    version=version,
    description=u"Snowflake Connector for Python",
    ext_modules=ext_modules,
    long_description=long_description,
    author='Snowflake, Inc',
    author_email='support@snowflake.com',
    license='Apache License, Version 2.0',
    keywords="Snowflake db database cloud analytics warehouse",
    url='https://www.snowflake.com/',
    download_url='https://www.snowflake.com/',
    use_2to3=False,

    # NOTE: Python 3.4 will be dropped within one month.
    python_requires='>=2.7.9,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*',

    install_requires=[
        'azure-common',
        'azure-storage-blob',
        'boto3>=1.4.4,<1.10.0',
        'botocore>=1.5.0,<1.13.0',
        'certifi',
        'future',
        'six',
        'pytz',
        'pycryptodomex>=3.2,!=3.5.0',
        'pyOpenSSL>=16.2.0',
        'cffi>=1.9',
        'cryptography>=1.8.2',
        'ijson',
        'pyjwt',
        'idna',
        'pyasn1>=0.4.0,<0.5.0;python_version<"3.0"',
        'pyasn1-modules>=0.2.0,<0.3.0;python_version<"3.0"',
        'enum34;python_version<"3.4"',
        'urllib3>=1.21.1,<1.25;python_version<"3.5"',
    ],

    namespace_packages=['snowflake'],
    packages=[
        'snowflake.connector',
        'snowflake.connector.tool',
    ],
    package_dir={
        'snowflake.connector': '.',
        'snowflake.connector.tool': 'tool',
    },
    package_data={
        'snowflake.connector': ['*.pem', '*.json', '*.rst', 'LICENSE.txt'],
    },

    entry_points={
        'console_scripts': [
            'snowflake-dump-ocsp-response = '
            'snowflake.connector.tool.dump_ocsp_response:main',
            'snowflake-dump-ocsp-response-cache = '
            'snowflake.connector.tool.dump_ocsp_response_cache:main',
            'snowflake-dump-certs = '
            'snowflake.connector.tool.dump_certs:main',
            'snowflake-export-certs = '
            'snowflake.connector.tool.export_certs:main',
        ],
    },
    extras_require={
        "secure-local-storage": [
            'keyring!=16.1.0'
        ],
        "arrow-result": [
            'pyarrow>=0.13.0;python_version>"3.4"',
            'pyarrow>=0.13.0;python_version<"3.0"'
        ]
    },

    classifiers=[
        'Development Status :: 5 - Production/Stable',

        'Environment :: Console',
        'Environment :: Other Environment',

        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',

        'License :: OSI Approved :: Apache Software License',

        'Operating System :: OS Independent',

        'Programming Language :: SQL',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',

        'Topic :: Database',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Scientific/Engineering :: Information Analysis',
    ],
)
