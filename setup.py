#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
from codecs import open
from os import path
import os
import sys
from sys import platform
from shutil import copy
import glob

from setuptools import setup, Extension

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

extensions = None
cmd_class = {}

isBuildExtEnabled = (os.getenv('ENABLE_EXT_MODULES', 'false')).lower()

if isBuildExtEnabled == 'true':
    from Cython.Distutils import build_ext
    from Cython.Build import cythonize
    import os
    import pyarrow

    extensions = cythonize(
        [
            Extension(name='snowflake.connector.arrow_iterator', sources=['arrow_iterator.pyx']),
            Extension(name='snowflake.connector.arrow_result', sources=['arrow_result.pyx'])
        ],
        build_dir=os.path.join('build', 'cython'))

    class MyBuildExt(build_ext):

        def build_extension(self, ext):
            current_dir = os.getcwd()

            if ext.name == 'snowflake.connector.arrow_iterator':
                self._copy_arrow_lib()

                ext.sources += ['cpp/ArrowIterator/CArrowChunkIterator.cpp',
                                'cpp/ArrowIterator/SnowflakeType.cpp',
                                'cpp/ArrowIterator/BinaryConverter.cpp',
                                'cpp/ArrowIterator/BooleanConverter.cpp',
                                'cpp/ArrowIterator/DecimalConverter.cpp',
                                'cpp/ArrowIterator/DateConverter.cpp',
                                'cpp/ArrowIterator/FloatConverter.cpp',
                                'cpp/ArrowIterator/IntConverter.cpp',
                                'cpp/ArrowIterator/StringConverter.cpp',
                                'cpp/ArrowIterator/TimeConverter.cpp',
                                'cpp/ArrowIterator/Python/Common.cpp',
                                'cpp/ArrowIterator/Python/Helpers.cpp',
                                'cpp/ArrowIterator/Util/time.cpp',
                                'cpp/Logging/logging.cpp']
                ext.include_dirs.append('cpp/ArrowIterator/')
                ext.include_dirs.append('cpp/Logging')
                ext.include_dirs.append(pyarrow.get_include())

                ext.extra_compile_args.append('-std=c++11')

                ext.library_dirs.append(os.path.join(current_dir, self.build_lib, 'snowflake', 'connector'))
                ext.extra_link_args += self._get_arrow_lib_as_linker_input()

                if self._is_unix():
                    ext.extra_link_args += ['-Wl,-rpath,$ORIGIN']

            build_ext.build_extension(self, ext)

        def _is_unix(self):
            return platform.startswith('linux') or platform == 'darwin'

        def _get_arrow_lib_dir(self):
            return pyarrow.get_library_dirs()[0]

        def _copy_arrow_lib(self):
            arrow_lib = self._get_libs_to_copy()

            for lib in arrow_lib:
                lib_pattern = self._get_pyarrow_lib_pattern(lib)
                source = glob.glob(lib_pattern)[0]
                copy(source, os.path.join(self.build_lib, 'snowflake', 'connector'))

        def _get_arrow_lib_as_linker_input(self):
            arrow_lib = pyarrow.get_libraries()
            link_lib = []
            for lib in arrow_lib:
                lib_pattern = self._get_pyarrow_lib_pattern(lib)
                source = glob.glob(lib_pattern)[0]
                link_lib.append(source)

            return link_lib

        def _get_libs_to_copy(self):
            if self._is_unix():
                return pyarrow.get_libraries() + \
                    ['arrow_flight', 'arrow_boost_regex', 'arrow_boost_system', 'arrow_boost_filesystem']
            elif platform == 'win32':
                return pyarrow.get_libraries() + ['arrow_flight']
            else:
                raise RuntimeError('Building on platform {} is not supported yet.'.format(platform))

        def _get_pyarrow_lib_pattern(self, lib_name):
            if platform.startswith('linux'):
                return '{}/lib{}.so*'.format(self._get_arrow_lib_dir(), lib_name)
            elif platform == 'darwin':
                return '{}/lib{}*dylib'.format(self._get_arrow_lib_dir(), lib_name)
            elif platform == 'win32':
                return '{}\\{}.lib'.format(self._get_arrow_lib_dir(), lib_name)
            else:
                raise RuntimeError('Building on platform {} is not supported yet.'.format(platform))

    cmd_class = {
        "build_ext": MyBuildExt
    }

setup(
    name='snowflake-connector-python',
    version=version,
    description=u"Snowflake Connector for Python",
    ext_modules=extensions,
    cmdclass=cmd_class,
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
            'pyarrow>=0.14.0;python_version>"3.4"',
            'pyarrow>=0.14.0;python_version<"3.0"'
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
