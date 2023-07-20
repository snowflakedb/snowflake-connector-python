#!/usr/bin/env python
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All rights reserved.
#

import os
import sys
import warnings

from setuptools import Extension, setup

CONNECTOR_SRC_DIR = os.path.join("src", "snowflake", "connector")
NANOARROW_SRC_DIR = os.path.join(CONNECTOR_SRC_DIR, "cpp", "ArrowIterator")

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
    from Cython.Build import cythonize
    from Cython.Distutils import build_ext

    _ABLE_TO_COMPILE_EXTENSIONS = True
except ImportError:
    warnings.warn(
        "Cannot compile native C code, because of a missing build dependency",
        stacklevel=2,
    )
    _ABLE_TO_COMPILE_EXTENSIONS = False

if _ABLE_TO_COMPILE_EXTENSIONS:
    extensions = cythonize(
        [
            Extension(
                name="snowflake.connector.arrow_iterator",
                sources=[os.path.join(NANOARROW_SRC_DIR, "arrow_iterator.pyx")],
                language="c++",
            ),
        ],
    )

    class MyBuildExt(build_ext):
        def build_extension(self, ext):
            if options["debug"]:
                ext.extra_compile_args.append("-g")
                ext.extra_link_args.append("-g")
            current_dir = os.getcwd()

            if ext.name == "snowflake.connector.arrow_iterator":
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
                    os.path.join(NANOARROW_SRC_DIR, "nanoarrow.c"),
                    os.path.join(NANOARROW_SRC_DIR, "nanoarrow_ipc.c"),
                    os.path.join(NANOARROW_SRC_DIR, "flatcc.c"),
                ]
                ext.include_dirs.append(ARROW_ITERATOR_SRC_DIR)
                ext.include_dirs.append(LOGGING_SRC_DIR)

                if sys.platform == "win32":
                    if not any("/std" not in s for s in ext.extra_compile_args):
                        ext.extra_compile_args.append("/std:c++17")
                elif sys.platform == "linux" or sys.platform == "darwin":
                    if "std=" not in os.environ.get("CXXFLAGS", ""):
                        ext.extra_compile_args.append("-std=c++17")
                        ext.extra_compile_args.append("-D_GLIBCXX_USE_CXX11_ABI=0")
                    if sys.platform == "darwin":
                        ext.extra_compile_args.append("-mmacosx-version-min=10.13")

                ext.library_dirs.append(
                    os.path.join(current_dir, self.build_lib, "snowflake", "connector")
                )

                # sys.platform for linux used to return with version suffix, (i.e. linux2, linux3)
                # After version 3.3, it will always be just 'linux'
                # https://docs.python.org/3/library/sys.html#sys.platform
                if sys.platform == "linux":
                    ext.extra_link_args += ["-Wl,-rpath,$ORIGIN"]
                elif sys.platform == "darwin":
                    # rpath,$ORIGIN only work on linux, did not work on darwin. use @loader_path instead
                    # fyi, https://medium.com/@donblas/fun-with-rpath-otool-and-install-name-tool-e3e41ae86172
                    ext.extra_link_args += ["-rpath", "@loader_path"]

            original__compile = self.compiler._compile

            def new__compile(obj, src: str, ext, cc_args, extra_postargs, pp_opts):
                if (
                    src.endswith("nanoarrow.c")
                    or src.endswith("nanoarrow_ipc.c")
                    or src.endswith("flatcc.c")
                ):
                    extra_postargs = [s for s in extra_postargs if s != "-std=c++17"]
                return original__compile(
                    obj, src, ext, cc_args, extra_postargs, pp_opts
                )

            self.compiler._compile = new__compile

            try:
                build_ext.build_extension(self, ext)
            finally:
                del self.compiler._compile
                self.compiler._compile = original__compile
            # build_ext.build_extension(self, ext)

    cmd_class = {"build_ext": MyBuildExt}

setup(
    version=version,
    ext_modules=extensions,
    cmdclass=cmd_class,
)
