#!/usr/bin/env python
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All rights reserved.
#

import os
import sys
import warnings
from shutil import copy

from setuptools import Extension, setup

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

    pyarrow_version = tuple(int(x) for x in pyarrow.__version__.split("."))
    extensions = cythonize(
        [
            Extension(
                name="snowflake.connector.arrow_iterator",
                sources=[os.path.join(CONNECTOR_SRC_DIR, "arrow_iterator.pyx")],
            ),
        ],
        compile_time_env=dict(ARROW_LESS_THAN_8=pyarrow_version < (8,)),
    )

    class MyBuildExt(build_ext):

        # list of libraries that will be bundled with python connector,
        # this list should be carefully examined when pyarrow lib is
        # upgraded
        arrow_libs_to_copy = {
            "linux": [
                "libarrow.so.1000",
                "libarrow_dataset.so.1000",
                "libarrow_python.so.1000",
                "libparquet.so.1000",
            ],
            "darwin": [
                "libarrow.1000.dylib",
                "libarrow_dataset.1000.dylib",
                "libarrow_python.1000.dylib",
                "libparquet.1000.dylib",
            ],
            "win32": [
                "arrow.dll",
                "arrow_dataset.dll",
                "arrow_python.dll",
                "parquet.dll",
            ],
        }

        arrow_libs_to_link = {
            "linux": [
                "libarrow.so.1000",
                "libarrow_dataset.so.1000",
                "libarrow_python.so.1000",
                "libparquet.so.1000",
            ],
            "darwin": [
                "libarrow.1000.dylib",
                "libarrow_dataset.1000.dylib",
                "libarrow_python.1000.dylib",
                "libparquet.1000.dylib",
            ],
            "win32": [
                "arrow.lib",
                "arrow_dataset.lib",
                "arrow_python.lib",
                "parquet.lib",
            ],
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
                    if not any("/std" not in s for s in ext.extra_compile_args):
                        ext.extra_compile_args.append("/std:c++17")
                    ext.include_dirs.append(pyarrow.get_include())
                    ext.include_dirs.append(numpy.get_include())
                elif sys.platform == "linux" or sys.platform == "darwin":
                    ext.extra_compile_args.append("-isystem" + pyarrow.get_include())
                    ext.extra_compile_args.append("-isystem" + numpy.get_include())
                    if "std=" not in os.environ.get("CXXFLAGS", ""):
                        ext.extra_compile_args.append("-std=c++17")
                        ext.extra_compile_args.append("-D_GLIBCXX_USE_CXX11_ABI=0")
                    if sys.platform == "darwin":
                        ext.extra_compile_args.append("-mmacosx-version-min=10.13")

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

            build_dir = os.path.join(self.build_lib, "snowflake", "connector")
            os.makedirs(build_dir, exist_ok=True)

            for lib in libs_to_bundle:
                source = f"{self._get_arrow_lib_dir()}/{lib}"
                copy(source, build_dir)

        def _get_arrow_lib_as_linker_input(self):
            link_lib = self.arrow_libs_to_link[sys.platform]
            ret = []

            for lib in link_lib:
                source = f"{self._get_arrow_lib_dir()}/{lib}"
                assert os.path.exists(source)
                ret.append(source)

            return ret

    cmd_class = {"build_ext": MyBuildExt}

setup(
    version=version,
    ext_modules=extensions,
    cmdclass=cmd_class,
)
