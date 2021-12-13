#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All rights reserved.
#
import os
import sys
import warnings
from codecs import open
from shutil import copy

from setuptools import Extension, find_namespace_packages, setup

CONNECTOR_SRC_DIR = os.path.join("src", "snowflake", "connector")

VERSION = (1, 1, 1, None)  # Default
try:
    with open(
        os.path.join(CONNECTOR_SRC_DIR, "generated_version.py"), encoding="utf-8"
    ) as f:
        exec(f.read())
except Exception:
    with open(os.path.join(CONNECTOR_SRC_DIR, "version.py"), encoding="utf-8") as f:
        exec(f.read())
version = ".".join([str(v) for v in VERSION if v is not None])

with open("DESCRIPTION.md", encoding="utf-8") as f:
    long_description = f.read()


# Parse command line flags

# This list defines the options definitions in a set
options_def = {
    "--debug",
}

# Options is the final parsed command line options
options = {e.lstrip("-"): False for e in options_def}

for flag in options_def:
    if flag in sys.argv:
        options[flag.lstrip("-")] = True
        sys.argv.remove(flag)

extensions = None
cmd_class = {}

pandas_requirements = [
    # Must be kept in sync with pyproject.toml
    "pyarrow>=6.0.0,<6.1.0",
    "pandas>=1.0.0,<1.4.0",
]

try:
    import numpy
    import pyarrow
    from Cython.Build import cythonize
    from Cython.Distutils import build_ext

    _ABLE_TO_COMPILE_EXTENSIONS = True
except ImportError:
    warnings.warn("Cannot compile native C code, because of a missing build dependency")
    _ABLE_TO_COMPILE_EXTENSIONS = False

if _ABLE_TO_COMPILE_EXTENSIONS:

    extensions = cythonize(
        [
            Extension(
                name="snowflake.connector.arrow_iterator",
                sources=[os.path.join(CONNECTOR_SRC_DIR, "arrow_iterator.pyx")],
            ),
        ],
    )

    class MyBuildExt(build_ext):

        # list of libraries that will be bundled with python connector,
        # this list should be carefully examined when pyarrow lib is
        # upgraded
        arrow_libs_to_copy = {
            "linux": ["libarrow.so.600", "libarrow_python.so.600"],
            "darwin": ["libarrow.600.dylib", "libarrow_python.600.dylib"],
            "win32": ["arrow.dll", "arrow_python.dll"],
        }

        arrow_libs_to_link = {
            "linux": ["libarrow.so.600", "libarrow_python.so.600"],
            "darwin": ["libarrow.600.dylib", "libarrow_python.600.dylib"],
            "win32": ["arrow.lib", "arrow_python.lib"],
        }

        def build_extension(self, ext):
            if options["debug"]:
                ext.extra_compile_args.append("-g")
                ext.extra_link_args.append("-g")
            current_dir = os.getcwd()

            if ext.name == "snowflake.connector.arrow_iterator":
                if not os.environ.get("SF_NO_COPY_ARROW_LIB", False):
                    self._copy_arrow_lib()
                CPP_SRC_DIR = os.path.join(CONNECTOR_SRC_DIR, "cpp")
                ARROW_ITERATOR_SRC_DIR = os.path.join(CPP_SRC_DIR, "ArrowIterator")
                LOGGING_SRC_DIR = os.path.join(CPP_SRC_DIR, "Logging")

                ext.sources += [
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "CArrowIterator.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "CArrowChunkIterator.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "CArrowTableIterator.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "SnowflakeType.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "BinaryConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "BooleanConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "DecimalConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "DateConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "FloatConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "IntConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "StringConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "TimeConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "TimeStampConverter.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "Python", "Common.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "Python", "Helpers.cpp"),
                    os.path.join(ARROW_ITERATOR_SRC_DIR, "Util", "time.cpp"),
                    LOGGING_SRC_DIR + "/logging.cpp",
                ]
                ext.include_dirs.append(ARROW_ITERATOR_SRC_DIR)
                ext.include_dirs.append(LOGGING_SRC_DIR)

                if sys.platform == "win32":
                    ext.include_dirs.append(pyarrow.get_include())
                    ext.include_dirs.append(numpy.get_include())
                elif sys.platform == "linux" or sys.platform == "darwin":
                    ext.extra_compile_args.append("-isystem" + pyarrow.get_include())
                    ext.extra_compile_args.append("-isystem" + numpy.get_include())
                    if "std=" not in os.environ.get("CXXFLAGS", ""):
                        ext.extra_compile_args.append("-std=c++11")
                        ext.extra_compile_args.append("-D_GLIBCXX_USE_CXX11_ABI=0")

                ext.library_dirs.append(
                    os.path.join(current_dir, self.build_lib, "snowflake", "connector")
                )
                ext.extra_link_args += self._get_arrow_lib_as_linker_input()

                # sys.platform for linux used to return with version suffix, (i.e. linux2, linux3)
                # After version 3.3, it will always be just 'linux'
                # https://docs.python.org/3/library/sys.html#sys.platform
                if sys.platform == "linux":
                    ext.extra_link_args += ["-Wl,-rpath,$ORIGIN"]
                elif sys.platform == "darwin":
                    # rpath,$ORIGIN only work on linux, did not work on darwin. use @loader_path instead
                    # fyi, https://medium.com/@donblas/fun-with-rpath-otool-and-install-name-tool-e3e41ae86172
                    ext.extra_link_args += ["-rpath", "@loader_path"]

            build_ext.build_extension(self, ext)

        def _get_arrow_lib_dir(self):
            if "SF_ARROW_LIBDIR" in os.environ:
                return os.environ["SF_ARROW_LIBDIR"]
            return pyarrow.get_library_dirs()[0]

        def _copy_arrow_lib(self):
            libs_to_bundle = self.arrow_libs_to_copy[sys.platform]

            for lib in libs_to_bundle:
                source = "{}/{}".format(self._get_arrow_lib_dir(), lib)
                build_dir = os.path.join(self.build_lib, "snowflake", "connector")
                copy(source, build_dir)

        def _get_arrow_lib_as_linker_input(self):
            link_lib = self.arrow_libs_to_link[sys.platform]
            ret = []

            for lib in link_lib:
                source = "{}/{}".format(self._get_arrow_lib_dir(), lib)
                assert os.path.exists(source)
                ret.append(source)

            return ret

    cmd_class = {"build_ext": MyBuildExt}

setup(
    name="snowflake-connector-python",
    version=version,
    description="Snowflake Connector for Python",
    ext_modules=extensions,
    cmdclass=cmd_class,
    long_description=long_description,
    author="Snowflake, Inc",
    author_email="ecosystem-team-dl@snowflake.com",
    license="Apache License, Version 2.0",
    keywords="Snowflake db database cloud analytics warehouse",
    url="https://www.snowflake.com/",
    project_urls={
        "Documentation": "https://docs.snowflake.com/",
        "Code": "https://github.com/snowflakedb/snowflake-connector-python",
        "Issue tracker": "https://github.com/snowflakedb/snowflake-connector-python/issues",
    },
    python_requires=">=3.6",
    install_requires=[
        # While requests is vendored, we use regular requests to perform OCSP checks
        "requests<3.0.0",
        "pytz",
        "pycryptodomex>=3.2,!=3.5.0,<4.0.0",
        "pyOpenSSL>=16.2.0,<22.0.0",
        "cffi>=1.9,<2.0.0",
        "cryptography>=3.1.0,<36.0.0",
        "pyjwt<3.0.0",
        "oscrypto<2.0.0",
        "asn1crypto>0.24.0,<2.0.0",
        'dataclasses<1.0;python_version=="3.6"',
        # A functioning pkg_resources.working_set.by_key and pkg_resources.Requirement is
        # required. Python 3.6 was released at the end of 2016. setuptools 34.0.0 was released
        # in early 2017, so we pick this version as a reasonably modern base.
        "setuptools>34.0.0",
        # requests requirements
        "charset_normalizer~=2.0.0",
        "idna>=2.5,<4",
        "certifi>=2017.4.17",
    ],
    namespace_packages=["snowflake"],
    packages=find_namespace_packages(
        where="src", include=["snowflake.*"], exclude=["snowflake.connector.cpp*"]
    ),
    package_dir={
        "": "src",
    },
    package_data={
        "snowflake.connector": [
            "*.md",
            "LICENSE.txt",
            "NOTICE",
            "src/snowflake/connector/py.typed",
        ],
    },
    entry_points={
        "console_scripts": [
            "snowflake-dump-ocsp-response = "
            "snowflake.connector.tool.dump_ocsp_response:main",
            "snowflake-dump-ocsp-response-cache = "
            "snowflake.connector.tool.dump_ocsp_response_cache:main",
            "snowflake-dump-certs = " "snowflake.connector.tool.dump_certs:main",
            "snowflake-export-certs = " "snowflake.connector.tool.export_certs:main",
        ],
    },
    extras_require={
        "secure-local-storage": [
            "keyring!=16.1.0,<24.0.0",
        ],
        "pandas": pandas_requirements,
        "development": [
            "pytest<6.3.0",
            "pytest-cov",
            "pytest-rerunfailures",
            "pytest-timeout",
            "pytest-xdist",
            "coverage",
            "pexpect",
            "mock",
            "pytz",
            "pytzdata",
            "Cython",
            "pendulum!=2.1.1",
            "more-itertools",
            "numpy<1.22.0",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Environment :: Other Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: SQL",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Database",
        "Topic :: Software Development",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Information Analysis",
    ],
    zip_safe=False,
)
