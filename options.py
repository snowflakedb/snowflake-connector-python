from .errors import MissingDependencyError

# Flags to see whether optional dependencies were installed
installed_pandas = False


class MissingPandas(object):

    def __getattr__(self, item):
        raise MissingDependencyError('pandas')


try:
    import pandas
    import pyarrow
    installed_pandas = True
except ImportError:
    pandas = MissingPandas()
    pyarrow = MissingPandas()
