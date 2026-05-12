#!/usr/bin/env python

import os
import platform
import shutil
import sys
import warnings

from setuptools import Extension, setup
from setuptools.command.egg_info import egg_info
from setuptools.command.sdist import sdist

CONNECTOR_SRC_DIR = os.path.join("src", "snowflake", "connector")
NANOARROW_SRC_DIR = os.path.join(CONNECTOR_SRC_DIR, "nanoarrow_cpp", "ArrowIterator")

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

_POSITIVE_VALUES = ("y", "yes", "t", "true", "1", "on")
SNOWFLAKE_DISABLE_COMPILE_ARROW_EXTENSIONS = (
    os.environ.get("SNOWFLAKE_DISABLE_COMPILE_ARROW_EXTENSIONS", "false").lower()
    in _POSITIVE_VALUES
)
SNOWFLAKE_NO_BOTO = (
    os.environ.get("SNOWFLAKE_NO_BOTO", "false").lower() in _POSITIVE_VALUES
)

try:
    from Cython.Build import cythonize
    from Cython.Distutils import build_ext

    _ABLE_TO_COMPILE_EXTENSIONS = True
except ImportError:
    warnings.warn(
        "Cannot compile native C code, because of a missing build dependency",
        stacklevel=1,
    )
    _ABLE_TO_COMPILE_EXTENSIONS = False

if _ABLE_TO_COMPILE_EXTENSIONS and not SNOWFLAKE_DISABLE_COMPILE_ARROW_EXTENSIONS:
    extensions = cythonize(
        [
            Extension(
                name="snowflake.connector.nanoarrow_arrow_iterator",
                sources=[
                    os.path.join(NANOARROW_SRC_DIR, "nanoarrow_arrow_iterator.pyx")
                ],
                language="c++",
            ),
        ],
    )

    class MyBuildExt(build_ext):
        def build_extension(self, ext):
            if options["debug"]:
                ext.extra_compile_args.append("-g")
                ext.extra_link_args.append("-g")
                ext.extra_compile_args.append("-O0")
                ext.extra_link_args.append("-O0")
            current_dir = os.getcwd()

            if ext.name == "snowflake.connector.nanoarrow_arrow_iterator":
                NANOARROW_CPP_SRC_DIR = os.path.join(CONNECTOR_SRC_DIR, "nanoarrow_cpp")
                NANOARROW_ARROW_ITERATOR_SRC_DIR = os.path.join(
                    NANOARROW_CPP_SRC_DIR, "ArrowIterator"
                )
                NANOARROW_LOGGING_SRC_DIR = os.path.join(
                    NANOARROW_CPP_SRC_DIR, "Logging"
                )

                ext.sources += [
                    os.path.join(
                        NANOARROW_ARROW_ITERATOR_SRC_DIR,
                        *((file,) if isinstance(file, str) else file),
                    )
                    for file in {
                        "ArrayConverter.cpp",
                        "BinaryConverter.cpp",
                        "BooleanConverter.cpp",
                        "CArrowChunkIterator.cpp",
                        "CArrowIterator.cpp",
                        "CArrowTableIterator.cpp",
                        "DateConverter.cpp",
                        "DecFloatConverter.cpp",
                        "DecimalConverter.cpp",
                        "FixedSizeListConverter.cpp",
                        "FloatConverter.cpp",
                        "IntConverter.cpp",
                        "IntervalConverter.cpp",
                        "MapConverter.cpp",
                        "ObjectConverter.cpp",
                        "SnowflakeType.cpp",
                        "StringConverter.cpp",
                        "TimeConverter.cpp",
                        "TimeStampConverter.cpp",
                        "flatcc.c",
                        "nanoarrow.c",
                        "nanoarrow_ipc.c",
                        ("Python", "Common.cpp"),
                        ("Python", "Helpers.cpp"),
                        ("Util", "time.cpp"),
                    }
                ]
                ext.sources.append(
                    os.path.join(NANOARROW_LOGGING_SRC_DIR, "logging.cpp")
                )
                ext.include_dirs.append(NANOARROW_ARROW_ITERATOR_SRC_DIR)
                ext.include_dirs.append(NANOARROW_LOGGING_SRC_DIR)

                if sys.platform == "win32":
                    if not any("/std" not in s for s in ext.extra_compile_args):
                        ext.extra_compile_args.append("/std:c++17")
                elif sys.platform == "linux" or sys.platform == "darwin":
                    if "std=" not in os.environ.get("CXXFLAGS", ""):
                        ext.extra_compile_args.append("-std=c++17")
                        ext.extra_compile_args.append("-D_GLIBCXX_USE_CXX11_ABI=0")
                    if (
                        sys.platform == "darwin"
                        and "macosx-version-min" not in os.environ.get("CXXFLAGS", "")
                    ):
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

            # the following is required by nanoarrow to compile c files
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
                self.compiler._compile = original__compile

    cmd_class = {"build_ext": MyBuildExt}


class SetDefaultInstallationExtras(egg_info):
    """Adds AWS extra unless SNOWFLAKE_NO_BOTO is specified."""

    def finalize_options(self):
        super().finalize_options()
        # if not explicitly excluded, add boto dependencies to install_requires
        if not SNOWFLAKE_NO_BOTO:
            boto_extras = self.distribution.extras_require.get("boto", [])
            self.distribution.install_requires += boto_extras


def _host_minicore_subdir():
    """Return the minicore/<platform> name matching the host, or None."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "aarch64"
    elif machine == "ppc64":
        arch = "ppc64"
    else:
        return None

    if system == "linux":
        libc, _ = platform.libc_ver()
        return f"linux_{arch}_{'glibc' if libc == 'glibc' else 'musl'}"
    if system == "darwin":
        return f"macos_{arch}"
    if system == "windows":
        return f"windows_{arch}"
    if system == "aix":
        return f"aix_{arch}"
    return None


class HostOnlyMinicoreSdist(sdist):
    # The sdist only ever needs the host's minicore binary — the runtime loader
    # opens one, and downstream packaging audits (Homebrew, conda-forge,
    # nixpkgs) reject foreign-arch binaries. Wheels are built from the git
    # tree, not the sdist, so keeping all platforms in git is fine.

    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        minicore_dir = os.path.join(
            base_dir, "src", "snowflake", "connector", "minicore"
        )
        if not os.path.isdir(minicore_dir):
            return
        keep = _host_minicore_subdir()
        if keep is None:
            raise RuntimeError(
                "Cannot build sdist: host platform "
                f"({platform.system()}/{platform.machine()}) has no matching "
                "minicore subdir. Build the sdist on a supported platform."
            )
        keep_path = os.path.join(minicore_dir, keep)
        if not os.path.isdir(keep_path):
            raise RuntimeError(
                f"Cannot build sdist: expected {keep_path} to exist. Run "
                "ci/download_minicore.py (or the normal wheel-build pipeline) "
                "to populate it before building the sdist."
            )
        for entry in os.listdir(minicore_dir):
            if entry == keep or entry.startswith("__"):
                continue
            full = os.path.join(minicore_dir, entry)
            if os.path.isdir(full):
                shutil.rmtree(full)


# Update command classes
cmd_class["egg_info"] = SetDefaultInstallationExtras
cmd_class["sdist"] = HostOnlyMinicoreSdist

setup(
    version=version,
    ext_modules=extensions,
    cmdclass=cmd_class,
)
