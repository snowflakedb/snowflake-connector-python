#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
from multiprocessing.pool import ThreadPool as p_ThreadPool
from concurrent.futures import ThreadPoolExecutor as t_ThreadPool
from logging import getLogger

logger = getLogger(__name__)

# This implements a wrapper around either
# multiprocessing.pool.ThreadPool or
# concurrent.futures.ThreadPoolExecutor, favoring process pools if
# they work. This is not a complete wrapper. It only wraps interfaces
# actually used by the snowflake connector. The behavior is not
# identical in that there is no equivalent of terminate(), but the
# behavior is close and should work fine based on the usage patterns
# in the code. In any case, without this, the connector is unusable in
# environments in which the process pool doesn't work, such as AWS
# lambda.


class ThreadPool:
    def _get_use_thread():
        try:
            p = p_ThreadPool(1)
            p.map(lambda: 1, [])
            p.close()
            p.join()
            logger.debug('using process pool')
            return False
        except Exception as e:
            logger.debug('process pool threw exception:', e,
                         '; using thread pool')
        return True

    _use_thread = _get_use_thread()

    def __init__(self, threads):
        if ThreadPool._use_thread:
            self.pool = t_ThreadPool(max_workers=threads)
            self.map = self._t_map
            self.apply_async = self._t_apply_async
            self.terminate = self._t_terminate
            self.close = self._t_close
            self.join = self._t_join
        else:
            self.pool = p_ThreadPool(threads)
            self.map = self._p_map
            self.apply_async = self._p_apply_async
            self.terminate = self._p_terminate
            self.close = self._p_close
            self.join = self._p_join

    def _p_map(self, *args, **kwargs):
        return self.pool.map(*args, **kwargs)

    def _p_apply_async(self, *args, **kwargs):
        return self.pool.apply_async(*args, **kwargs)

    def _p_terminate(self, *args, **kwargs):
        return self.pool.terminate(*args, **kwargs)

    def _p_close(self, *args, **kwargs):
        return self.pool.close(*args, **kwargs)

    def _p_join(self, *args, **kwargs):
        return self.pool.join(*args, **kwargs)

    def _t_map(self, *args, **kwargs):
        return self.pool.map(*args, **kwargs)

    def _t_apply_async(self, *args, **kwargs):
        return self.pool.submit(args[0], *args[1])

    def _t_terminate(self, *args, **kwargs):
        if self.pool:
            self.pool.shutdown(wait=False)
            self.pool = None

    def _t_close(self, *args, **kwargs):
        pass

    def _t_join(self, *args, **kwargs):
        if self.pool:
            self.pool.shutdown(wait=True)
            self.pool = None
