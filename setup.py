#!/usr/bin/env python

import os
import platform
import shutil
import sys

from setuptools import setup
from setuptools.command.build_ext import build_ext
from setuptools.command.build_py import build_py

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

cmd_class = {}

_POSITIVE_VALUES = ("y", "yes", "t", "true", "1", "on")
SNOWFLAKE_DISABLE_COMPILE_ARROW_EXTENSIONS = (
    os.environ.get("SNOWFLAKE_DISABLE_COMPILE_ARROW_EXTENSIONS", "false").lower()
    in _POSITIVE_VALUES
)

# Extension sources/include dirs live in pyproject.toml ([tool.setuptools.ext-modules]).
# Keep this block indented like the old cythonize path so the platform-flag diff stays small.
if True:
    class MyBuildExt(build_ext):
        def finalize_options(self):
            super().finalize_options()
            # Clear after pyproject.toml is applied so the env var wins under PEP 517.
            if SNOWFLAKE_DISABLE_COMPILE_ARROW_EXTENSIONS:
                self.extensions = []
                self.distribution.ext_modules = []

        def run(self):
            if SNOWFLAKE_DISABLE_COMPILE_ARROW_EXTENSIONS:
                # Drop stale extension artifacts from a previous compile in build/.
                build_lib = getattr(self, "build_lib", None)
                if build_lib:
                    connector_dir = os.path.join(build_lib, "snowflake", "connector")
                    if os.path.isdir(connector_dir):
                        for name in os.listdir(connector_dir):
                            if name.startswith("nanoarrow_arrow_iterator."):
                                os.remove(os.path.join(connector_dir, name))
                return
            super().run()

        def build_extension(self, ext):
            if options["debug"]:
                ext.extra_compile_args.append("-g")
                ext.extra_link_args.append("-g")
                ext.extra_compile_args.append("-O0")
                ext.extra_link_args.append("-O0")
            current_dir = os.getcwd()

            if ext.name == "snowflake.connector.nanoarrow_arrow_iterator":
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


def _minicore_native_subdir():
    """Return the minicore/<platform> subdir matching the current interpreter.

    Mirrors snowflake.connector._utils._CoreLoader._get_platform_subdir so the
    build-time pruner and the runtime loader always agree on the layout.
    Returns None when the platform is not recognised (leave tree untouched).
    """
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
        libc_family = "glibc" if libc == "glibc" else "musl"
        return f"linux_{arch}_{libc_family}"
    if system == "darwin":
        return f"macos_{arch}"
    if system == "windows":
        return f"windows_{arch}"
    if system == "aix":
        return f"aix_{arch}"
    return None


class PlatformBuildPy(build_py):
    """Strip non-native minicore/<platform>/ dirs from the built distribution.

    The sdist ships minicore binaries for every supported platform. At
    build-time we keep only the one matching the current interpreter so wheels
    and downstream sdist consumers (pip install, Homebrew, conda-forge,
    nixpkgs) end up with a clean single-platform layout.
    """

    def run(self):
        super().run()
        self._prune_minicore()

    def _prune_minicore(self):
        minicore_build_dir = os.path.join(
            self.build_lib, "snowflake", "connector", "minicore"
        )
        if not os.path.isdir(minicore_build_dir):
            return
        keep = _minicore_native_subdir()
        if keep is None:
            return
        for entry in os.listdir(minicore_build_dir):
            full = os.path.join(minicore_build_dir, entry)
            if not os.path.isdir(full) or entry.startswith("__"):
                continue
            if entry == keep:
                continue
            shutil.rmtree(full)


# Update command classes
cmd_class["build_py"] = PlatformBuildPy

setup(
    cmdclass=cmd_class,
)
