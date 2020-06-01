#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import os
import sys
from codecs import open
from os import path
from shutil import copy
from sys import platform

from setuptools import Extension, setup

THIS_DIR = path.dirname(path.realpath(__file__))

try:
    from generated_version import VERSION
except Exception:
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
    import numpy

    extensions = cythonize(
        [
            Extension(name='snowflake.connector.arrow_iterator', sources=['arrow_iterator.pyx']),
            Extension(name='snowflake.connector.arrow_result', sources=['arrow_result.pyx'])
        ],
        build_dir=os.path.join('build', 'cython'))

    class MyBuildExt(build_ext):

        # list of libraries that will be bundled with python connector,
        # this list should be carefully examined when pyarrow lib is
        # upgraded
        arrow_libs_to_copy = {
            'linux': ['libarrow.so.17',
                      'libarrow_python.so.17',
                      'libarrow_flight.so.17'],
            'darwin': ['libarrow.17.dylib',
                       'libarrow_python.17.dylib'],
            'win32': ['arrow.dll',
                      'arrow_python.dll',
                      'zlib.dll']
        }

        arrow_libs_to_link = {
            'linux': ['libarrow.so.17',
                      'libarrow_python.so.17'],
            'darwin': ['libarrow.17.dylib',
                       'libarrow_python.17.dylib'],
            'win32': ['arrow.lib',
                      'arrow_python.lib']
        }

        def build_extension(self, ext):
            current_dir = os.getcwd()

            if ext.name == 'snowflake.connector.arrow_iterator':
                self._copy_arrow_lib()

                ext.sources += ['cpp/ArrowIterator/CArrowIterator.cpp',
                                'cpp/ArrowIterator/CArrowChunkIterator.cpp',
                                'cpp/ArrowIterator/CArrowTableIterator.cpp',
                                'cpp/ArrowIterator/SnowflakeType.cpp',
                                'cpp/ArrowIterator/BinaryConverter.cpp',
                                'cpp/ArrowIterator/BooleanConverter.cpp',
                                'cpp/ArrowIterator/DecimalConverter.cpp',
                                'cpp/ArrowIterator/DateConverter.cpp',
                                'cpp/ArrowIterator/FloatConverter.cpp',
                                'cpp/ArrowIterator/IntConverter.cpp',
                                'cpp/ArrowIterator/StringConverter.cpp',
                                'cpp/ArrowIterator/TimeConverter.cpp',
                                'cpp/ArrowIterator/TimeStampConverter.cpp',
                                'cpp/ArrowIterator/Python/Common.cpp',
                                'cpp/ArrowIterator/Python/Helpers.cpp',
                                'cpp/ArrowIterator/Util/time.cpp',
                                'cpp/Logging/logging.cpp']
                ext.include_dirs.append('cpp/ArrowIterator/')
                ext.include_dirs.append('cpp/Logging')

                if platform == 'win32':
                    ext.include_dirs.append(pyarrow.get_include())
                    ext.include_dirs.append(numpy.get_include())
                elif platform == 'linux' or platform == 'darwin':
                    ext.extra_compile_args.append('-isystem' + pyarrow.get_include())
                    ext.extra_compile_args.append('-isystem' + numpy.get_include())
                    ext.extra_compile_args.append('-std=c++11')
                    ext.extra_compile_args.append('-D_GLIBCXX_USE_CXX11_ABI=0')

                ext.library_dirs.append(os.path.join(current_dir, self.build_lib, 'snowflake', 'connector'))
                ext.extra_link_args += self._get_arrow_lib_as_linker_input()

                # sys.platform for linux used to return with version suffix, (i.e. linux2, linux3)
                # After version 3.3, it will always be just 'linux'
                # https://docs.python.org/3/library/sys.html#sys.platform
                if platform == 'linux':
                    ext.extra_link_args += ['-Wl,-rpath,$ORIGIN']
                elif platform == 'darwin':
                    # rpath,$ORIGIN only work on linux, did not work on darwin. use @loader_path instead
                    # fyi, https://medium.com/@donblas/fun-with-rpath-otool-and-install-name-tool-e3e41ae86172
                    ext.extra_link_args += ['-rpath', '@loader_path']

            build_ext.build_extension(self, ext)

        def _get_arrow_lib_dir(self):
            return pyarrow.get_library_dirs()[0]

        def _copy_arrow_lib(self):
            libs_to_bundle = self.arrow_libs_to_copy[sys.platform]

            for lib in libs_to_bundle:
                source = '{}/{}'.format(self._get_arrow_lib_dir(), lib)
                build_dir = path.join(self.build_lib, 'snowflake', 'connector')
                copy(source, build_dir)

        def _get_arrow_lib_as_linker_input(self):
            link_lib = self.arrow_libs_to_link[sys.platform]
            ret = []

            for lib in link_lib:
                source = '{}/{}'.format(self._get_arrow_lib_dir(), lib)
                assert path.exists(source)
                ret.append(source)

            return ret

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

    python_requires='>=3.5',

    install_requires=[
        'azure-common<2.0.0',
        'azure-storage-blob<12.0.0;python_version<="3.5.1"',
        'azure-storage-blob>=12.0.0,<13.0.0;python_version>="3.5.2"',
        'boto3>=1.4.4,<1.14',
        'requests<2.24.0',
        'urllib3>=1.20,<1.26.0',
        'certifi<2021.0.0',
        'pytz<2021.0',
        'pycryptodomex>=3.2,!=3.5.0,<4.0.0',
        'pyOpenSSL>=16.2.0,<21.0.0',
        'cffi>=1.9,<1.14',
        'cryptography>=2.5.0,<3.0.0',
        'ijson<3.0.0',
        'pyjwt<2.0.0',
        'idna<2.10',
        'oscrypto<2.0.0',
        'asn1crypto>0.24.0,<2.0.0',
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
            'keyring<22.0.0,!=16.1.0',
        ],
        "pandas": [
            'pyarrow>=0.17.0,<0.18.0',
            'pandas==0.24.2;python_version=="3.5"',
            'pandas>=1.0.0,<1.1.0;python_version>"3.5"',
        ],
        "development": [
            'pytest',
            'pytest-cov',
            'pytest-rerunfailures',
            'pytest-timeout',
            'coverage',
            'pexpect',
            'mock',
            'pytz',
            'pytzdata',
            'Cython',
            'pendulum',
            'more-itertools',
            'numpy',
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
