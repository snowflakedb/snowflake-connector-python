#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import shutil
import time

OCSP_CACHE_DIR = "/Users/yqiu/Library/Caches/Snowflake/"


def clear_OCSP_cache_dir():
    try:
        shutil.rmtree(OCSP_CACHE_DIR)
    except:
        pass


def wrap_method_with_timer(cls, method_str, log_file):
    old_method = getattr(cls, method_str)

    def new_method(*args, **kwargs):
        start_time = time.time()
        print(f"Calling original method {old_method} with logging to {log_file}")
        ret = old_method(*args, **kwargs)
        end_time = time.time()
        print(f"Call completed with time {end_time - start_time}")
        log_file.write(f"{end_time - start_time}\n")
        return ret

    setattr(cls, method_str, new_method)


def wrap_method_with_timer_async(cls, method_str, log_file):
    old_method = getattr(cls, method_str)

    async def new_method(*args, **kwargs):
        start_time = time.time()
        print(f"Calling original method {old_method} with logging to {log_file}")
        ret = await old_method(*args, **kwargs)
        end_time = time.time()
        print(f"Call completed with time {end_time - start_time}")
        log_file.write(f"{end_time - start_time}\n")
        return ret

    setattr(cls, method_str, new_method)


def wrap_function(log_file):
    def decor(func):
        def new_func(*args, **kwargs):
            start_time = time.time()
            print(f"Calling original function {func} with logging to {log_file}")
            ret = func(*args, **kwargs)
            end_time = time.time()
            print(f"Call completed with time {end_time - start_time}")
            log_file.write(f"{end_time - start_time}\n")
            return ret

        return new_func

    return decor


def read_file_to_float_list(file_str):
    with open(file_str) as f:
        return [float(s) for s in f.read().splitlines()]
