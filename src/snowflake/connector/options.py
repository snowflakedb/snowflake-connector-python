from __future__ import annotations

import importlib
import os
import warnings
from importlib.metadata import PackageNotFoundError, distribution
from logging import getLogger
from types import ModuleType
from typing import Union

from packaging.requirements import Requirement

from . import errors

logger = getLogger(__name__)

"""This module helps to manage optional dependencies.

It implements MissingOptionalDependency as a base class. If a module is unavailable an instance of this will be
returned. These derived classes can be seen in this file pre-defined. The point of these classes is that if someone
tries to use pyarrow code then by importing pyarrow from this module if they did pyarrow.xxx then that would raise
a MissingDependencyError.
"""


class MissingOptionalDependency:
    """A class to replace missing dependencies.

    The only thing this class is supposed to do is raise a MissingDependencyError when __getattr__ is called.
    This will be triggered whenever module.member is going to be called.
    """

    _dep_name = "not set"

    def __getattr__(self, item):
        raise errors.MissingDependencyError(self._dep_name)


class MissingPandas(MissingOptionalDependency):
    """The class is specifically for pandas optional dependency."""

    _dep_name = "pandas"


class MissingPyarrow(MissingOptionalDependency):
    """The class is specifically for pyarrow optional dependency."""

    _dep_name = "pyarrow"


class MissingKeyring(MissingOptionalDependency):
    """The class is specifically for sso optional dependency."""

    _dep_name = "keyring"


class MissingBotocore(MissingOptionalDependency):
    """The class is specifically for boto optional dependency."""

    _dep_name = "botocore"


class MissingBoto3(MissingOptionalDependency):
    """The class is specifically for boto3 optional dependency."""

    _dep_name = "boto3"


class MissingAioBotocore(MissingOptionalDependency):
    """The class is specifically for boto optional dependency."""

    _dep_name = "aiobotocore"


class MissingAioBoto3(MissingOptionalDependency):
    """The class is specifically for boto3 optional dependency."""

    _dep_name = "aioboto3"


class MissingAzureIdentity(MissingOptionalDependency):
    """The class is specifically for azure-identity optional dependency."""

    _dep_name = "azure-identity"


ModuleLikeObject = Union[ModuleType, MissingOptionalDependency]


def warn_incompatible_dep(
    dep_name: str, installed_ver: str, expected_ver: Requirement
) -> None:
    warnings.warn(
        "You have an incompatible version of '{}' installed ({}), please install a version that "
        "adheres to: '{}'".format(dep_name, installed_ver, expected_ver),
        stacklevel=2,
    )


_PANDAS_INSTALL_LINK = (
    "https://docs.snowflake.com/en/user-guide/python-connector-pandas.html#installation"
)


def missing_pandas_extra_message() -> str:
    """Build an error message naming which pandas-extra packages failed to import.

    ``installed_pandas`` is only true when both pandas and pyarrow import. Blame
    whichever package is actually missing so callers are not told to install
    pandas when only pyarrow is absent.
    """
    missing: list[str] = []
    if isinstance(pandas, MissingOptionalDependency):
        missing.append(pandas._dep_name)
    if isinstance(pyarrow, MissingOptionalDependency):
        missing.append(pyarrow._dep_name)
    # Flag-only failures (for example unit-test mocks) still need a message.
    if not missing:
        missing = ["pandas"]
    if len(missing) == 1:
        deps = f"'{missing[0]}'"
        noun, verb = "dependency", "is"
    else:
        deps = " and ".join(f"'{name}'" for name in missing)
        noun, verb = "dependencies", "are"
    return (
        f"Optional {noun}: {deps} {verb} not installed, please see the following link "
        f"for install instructions: {_PANDAS_INSTALL_LINK}"
    )


def _import_or_missing_pandas_option() -> (
    tuple[ModuleLikeObject, ModuleLikeObject, bool]
):
    """This function tries importing the following packages: pandas, pyarrow.

    If available it returns pandas and pyarrow packages with a flag of whether they were imported.
    It also warns users if they have an unsupported pyarrow version installed if possible.
    """
    pandas_mod: ModuleLikeObject = MissingPandas()
    pyarrow_mod: ModuleLikeObject = MissingPyarrow()

    try:
        pandas_mod = importlib.import_module("pandas")
        # since we enable relative imports without dots this import gives us an issues when ran from test directory
        from pandas import DataFrame  # NOQA
    except ImportError:
        pandas_mod = MissingPandas()

    try:
        pyarrow_mod = importlib.import_module("pyarrow")

        # set default memory pool to system for pyarrow to_pandas conversion
        if "ARROW_DEFAULT_MEMORY_POOL" not in os.environ:
            os.environ["ARROW_DEFAULT_MEMORY_POOL"] = "system"

        # Check whether we have the currently supported pyarrow installed
        try:
            pyarrow_dist = distribution("pyarrow")
            snowflake_connector_dist = distribution("snowflake-connector-python")

            dependencies = snowflake_connector_dist.metadata.get_all(
                "Requires-Dist", []
            )
            pandas_pyarrow_extra = None
            for dependency in dependencies:
                dep = Requirement(dependency)
                if (
                    dep.marker is not None
                    and dep.marker.evaluate({"extra": "pandas"})
                    and dep.name == "pyarrow"
                ):
                    pandas_pyarrow_extra = dep
                    break

            installed_pyarrow_version = pyarrow_dist.version
            if (
                pandas_pyarrow_extra is not None
                and not pandas_pyarrow_extra.specifier.contains(
                    installed_pyarrow_version
                )
            ):
                warn_incompatible_dep(
                    "pyarrow", installed_pyarrow_version, pandas_pyarrow_extra
                )

        except PackageNotFoundError as e:
            logger.info(
                f"Cannot determine if compatible pyarrow is installed because of missing package(s): {e}"
            )
    except ImportError:
        pyarrow_mod = MissingPyarrow()

    installed = not isinstance(pandas_mod, MissingOptionalDependency) and not isinstance(
        pyarrow_mod, MissingOptionalDependency
    )
    return pandas_mod, pyarrow_mod, installed


def _import_or_missing_keyring_option() -> tuple[ModuleLikeObject, bool]:
    """This function tries importing the following packages: keyring.

    If available it returns keyring package with a flag of whether it was imported.
    """
    try:
        keyring = importlib.import_module("keyring")
        return keyring, True
    except ImportError:
        return MissingKeyring(), False


def _import_or_missing_boto_option() -> tuple[ModuleLikeObject, ModuleLikeObject, bool]:
    """This function tries importing the following packages: botocore and boto3."""
    try:
        botocore = importlib.import_module("botocore")
        boto3 = importlib.import_module("boto3")
        return botocore, boto3, True
    except ImportError:
        return MissingBotocore(), MissingBoto3(), False


def _import_or_missing_aioboto_option() -> (
    tuple[ModuleLikeObject, ModuleLikeObject, bool]
):
    """This function tries importing the following packages: botocore and boto3."""
    try:
        aiobotocore = importlib.import_module("aiobotocore")
        aioboto3 = importlib.import_module("aioboto3")
        return aiobotocore, aioboto3, True
    except ImportError:
        return MissingAioBotocore(), MissingAioBoto3(), False


def _import_or_missing_azure_identity_option() -> (
    tuple[ModuleLikeObject, ModuleLikeObject, bool]
):
    """This function tries importing azure.identity and azure.identity.aio."""
    try:
        azure_identity = importlib.import_module("azure.identity")
        azure_identity_aio = importlib.import_module("azure.identity.aio")
        return azure_identity, azure_identity_aio, True
    except ImportError:
        return MissingAzureIdentity(), MissingAzureIdentity(), False


# Create actual constants to be imported from this file
pandas, pyarrow, installed_pandas = _import_or_missing_pandas_option()
keyring, installed_keyring = _import_or_missing_keyring_option()
botocore, boto3, installed_boto = _import_or_missing_boto_option()
aiobotocore, aioboto3, installed_aioboto = _import_or_missing_aioboto_option()
azure_identity, azure_identity_aio, installed_azure_identity = (
    _import_or_missing_azure_identity_option()
)
