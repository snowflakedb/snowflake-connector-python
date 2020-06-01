import warnings
import pkg_resources

from .errors import MissingDependencyError

# Flags to see whether optional dependencies were installed
installed_pandas = False
installed_keyring = False


def warn_incompatible_dep(dep_name: str,
                          installed_ver: str,
                          expected_ver: 'pkg_resources.Requirement') -> None:
    warnings.warn(
        "You have an incompatible version of '{}' installed, please install a version that "
        "adheres to: '{}'".format(dep_name,
                                  _expected_version),
        stacklevel=2)


class MissingPandas(object):

    def __getattr__(self, item):
        raise MissingDependencyError('pandas')


try:
    import pandas
    # since we enable relative imports without dots this import gives us an issues when ran from test directory
    from pandas import DataFrame  # NOQA
    import pyarrow

    installed_pandas = True
    # Make sure we have the right pyarrow installed
    _pandas_extras = pkg_resources.working_set.by_key['snowflake-connector-python']._dep_map['pandas']
    _expected_version = [dep for dep in _pandas_extras if dep.name == 'pyarrow'][0]
    _installed_pyarrow = pkg_resources.working_set.by_key['pyarrow']
    if _installed_pyarrow and _installed_pyarrow.version not in _expected_version:
        warn_incompatible_dep('pyarrow', _installed_pyarrow.version, _expected_version)
except ImportError:
    pandas = MissingPandas()
    pyarrow = MissingPandas()

try:
    import keyring

    installed_keyring = True
except ImportError:
    keyring = None
