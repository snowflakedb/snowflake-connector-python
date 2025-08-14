PROBES_FUNCTIONS = {}


def prober_function(func):
    """
    Register a function in the PROBES_FUNCTIONS dictionary.
    The key is the function name, and the value is the function itself.
    """
    PROBES_FUNCTIONS[func.__name__] = func
    return func
