#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
from codecs import open
from os import path

from setuptools import setup

THIS_DIR = path.dirname(path.realpath(__file__))

try:
    from generated_version import VERSION
except:
    from version import VERSION
version = '.'.join([str(v) for v in VERSION if v is not None])

with open(path.join(THIS_DIR, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='snowflake-connector-python',
    version=version,
    description=u"Snowflake Connector for Python",
    long_description=long_description,
    author='Snowflake Computing, Inc',
    author_email='support@snowflake.net',
    license='Apache License, Version 2.0',
    keywords="Snowflake db database cloud analytics warehouse",
    url='https://www.snowflake.net/',
    download_url='https://www.snowflake.net/',
    use_2to3=False,

    install_requires=[
        'azure-common<2',
        'azure_nspkg<3',
        'azure-storage<=0.34.2',
        'boto3>=1.4.4,<1.7.0',
        'botocore>=1.5.0,<1.10.0',
        'certifi',
        'future',
        'six',
        'pytz',
        'pycryptodome>=3.2,!=3.5.0',
        'pyOpenSSL>=16.2.0,<18.0.0',
        'cffi>=1.9',
        'cryptography>=1.8.2,<2.2',
        'ijson',
        'pyjwt',
        'pyasn1>=0.2.1,<0.5.0',  # added back for Python 2
        'pyasn1-modules>=0.0.8,<0.3.0',  # added back for Python 2
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
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',

        'Topic :: Database',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Scientific/Engineering :: Information Analysis',
    ],
)
