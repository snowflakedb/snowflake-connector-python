#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import warnings
from logging import getLogger

import pkg_resources

from .errors import MissingDependencyError

# Flags to see whether optional dependencies were installed
installed_pandas = False
installed_keyring = False

logger = getLogger(__name__)


def warn_incompatible_dep(dep_name: str,
                          installed_ver: str,
                          expected_ver: 'pkg_resources.Requirement') -> None:
    warnings.warn(
        "You have an incompatible version of '{}' installed, please install a version that "
        "adheres to: '{}'".format(dep_name, _expected_pyarrow_version),
        stacklevel=2)


class MissingPandas(object):

    def __getattr__(self, item):
        raise MissingDependencyError('pandas')


try:
    import pandas  # NOQA
    # since we enable relative imports without dots this import gives us an issues when ran from test directory
    from pandas import DataFrame  # NOQA
    import pyarrow  # NOQA

    installed_pandas = True
    # Make sure we have the right pyarrow installed
    installed_packages = pkg_resources.working_set.by_key
    if all(k in installed_packages for k in ("snowflake-connector-python", "pyarrow")):
        _pandas_extras = installed_packages['snowflake-connector-python']._dep_map['pandas']
        _expected_pyarrow_version = [dep for dep in _pandas_extras if dep.name == 'pyarrow'][0]
        _installed_pyarrow_version = installed_packages['pyarrow']
        if _installed_pyarrow_version and _installed_pyarrow_version.version not in _expected_pyarrow_version:
            warn_incompatible_dep('pyarrow', _installed_pyarrow_version.version, _expected_pyarrow_version)
    else:
        logger.info("Cannot determine if compatible pyarrow is installed because of missing package(s) from "
                    "{}".format(installed_packages.keys()))
except ImportError:
    pandas = MissingPandas()
    pyarrow = MissingPandas()

try:
    import keyring  # NOQA

    installed_keyring = True
except ImportError:
    keyring = None
