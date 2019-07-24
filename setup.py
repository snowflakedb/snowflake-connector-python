#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
from codecs import open
from os import path
import os
import subprocess
import sys

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

THIS_DIR = path.dirname(path.realpath(__file__))

try:
    from generated_version import VERSION
except:
    from version import VERSION
version = '.'.join([str(v) for v in VERSION if v is not None])

with open(path.join(THIS_DIR, 'DESCRIPTION.rst'), encoding='utf-8') as f:
    long_description = f.read()


# Parse command line flags
options = {k: 'OFF' for k in ['--opt', '--debug']}
for flag in options.keys():
    if flag in sys.argv:
        options[flag] = 'ON'
        sys.argv.remove(flag)

# Command line flags forwarded to CMake
cmake_cmd_args = []
for f in sys.argv:
    if f.startswith('-D'):
        cmake_cmd_args.append(f)

for f in cmake_cmd_args:
    sys.argv.remove(f)


class CMakeExtension(Extension):
    def __init__(self, name, cmake_lists_dir='.', sources=[], **kwa):
        Extension.__init__(self, name, sources=sources, **kwa)
        self.cmake_lists_dir = os.path.abspath(cmake_lists_dir)


extension = None
cmd_class = None

isBuildExtEnabled = (os.getenv('ENABLE_EXT_MODULES', 'false')).lower()

if isBuildExtEnabled == 'true':
    from Cython.Build import cythonize
    cython_build_dir = os.path.join('build', 'cython')
    cython_extension = cythonize(["arrow_result.pyx"], build_dir=cython_build_dir)
    extension = cython_extension + [
        CMakeExtension(name="snowflake.connector.arrow_iterator", cmake_lists_dir="cpp")
    ]
    cmd_class = {
        "buld_ext": CMakeExtension
    }


class CMakeBuild(build_ext):

    def build_extensions(self):
        try:
            subprocess.check_output(['cmake', '--version'])
        except OSError:
            raise RuntimeError('Cannot find CMake executable')

        for ext in self.extensions:

            if isinstance(ext, CMakeExtension):
                print('Building CMake Extension: {}'.format(ext.name))

                extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
                cfg = 'Debug' if options['--debug'] == 'ON' else 'Release'

                cmake_args = [
                    '-DCMAKE_BUILD_TYPE=%s' % cfg,
                    '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{}={}'.format(cfg.upper(), extdir),
                    '-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_{}={}'.format(cfg.upper(), self.build_temp),
                    '-DPYTHON_EXECUTABLE={}'.format(sys.executable),
                ]

                cmake_args += cmake_cmd_args

                if not os.path.exists(self.build_temp):
                    os.makedirs(self.build_temp)

                # Config and build the extension
                subprocess.check_call(['cmake', ext.cmake_lists_dir] + cmake_args,
                                      cwd=self.build_temp)
                subprocess.check_call(['cmake', '--build', '.', '--config', cfg],
                                      cwd=self.build_temp)
            else:
                build_ext.build_extension(self, ext)


setup(
    name='snowflake-connector-python',
    version=version,
    description=u"Snowflake Connector for Python",
    ext_modules=extension,
    cmdclass={
        'build_ext': CMakeBuild
    },
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
