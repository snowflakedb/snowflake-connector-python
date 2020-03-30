from .errors import MissingDependencyError

# Flags to see whether optional dependencies were installed
installed_pandas = False
installed_keyring = False


class MissingPandas(object):

    def __getattr__(self, item):
        raise MissingDependencyError('pandas')


class MissingKeyring(object):

    def __getattr__(self, item):
        raise MissingDependencyError('keyring')


try:
    import pandas
    import pyarrow
    installed_pandas = True
except ImportError:
    pandas = MissingPandas()
    pyarrow = MissingPandas()

try:
    import keyring
    installed_keyring = True
except ImportError:
    keyring = MissingKeyring()
