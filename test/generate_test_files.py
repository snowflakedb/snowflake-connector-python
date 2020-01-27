#!/usr/bin/env python3
import platform
import random
import subprocess
import time
import tempfile
import os

import argparse

IS_WINDOWS = platform.system() == 'Windows'


def generate_k_lines_of_n_files(k, n, compress=False, tmp_dir=None):
    """
    Create testing files
    BEWARE returned path has to be deleted by caller
    :param k: number of lines per file to generate
    :param n: number of files to generate
    :param compress: whether to compress the files
    :param tmp_dir: location where the files should be generated, if not supplied a temp directory will be created
    :return: path to parent folder to newly generated files
    """
    if tmp_dir is None:
        tmp_dir = tempfile.mkdtemp(prefix='data')
    for i in range(n):
        with open(os.path.join(tmp_dir, 'file{0}'.format(i)), 'w',
                  encoding='utf-8') as f:
            for j in range(k):
                num = int(random.random() * 10000.0)
                tm = time.gmtime(
                    int(random.random() * 30000.0) - 15000)
                dt = time.strftime('%Y-%m-%d', tm)
                tm = time.gmtime(
                    int(random.random() * 30000.0) - 15000)
                ts = time.strftime('%Y-%m-%d %H:%M:%S', tm)
                tm = time.gmtime(
                    int(random.random() * 30000.0) - 15000)
                tsltz = time.strftime('%Y-%m-%d %H:%M:%S', tm)
                tm = time.gmtime(
                    int(random.random() * 30000.0) - 15000)
                tsntz = time.strftime('%Y-%m-%d %H:%M:%S', tm)
                tm = time.gmtime(
                    int(random.random() * 30000.0) - 15000)
                tstz = time.strftime('%Y-%m-%dT%H:%M:%S', tm) + \
                       ('-' if random.random() < 0.5 else '+') + \
                       "{0:02d}:{1:02d}".format(
                           int(random.random() * 12.0),
                           int(random.random() * 60.0))
                pct = random.random() * 1000.0
                ratio = u"{0:5.2f}".format(random.random() * 1000.0)
                rec = u"{0:d},{1:s},{2:s},{3:s},{4:s},{5:s},{6:f},{7:s}".format(
                    num, dt, ts, tsltz, tsntz, tstz,
                    pct,
                    ratio)
                f.write(rec + "\n")
        if compress:
            if not IS_WINDOWS:
                subprocess.Popen(
                    ['gzip', os.path.join(tmp_dir, 'file{0}'.format(i))],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE).communicate()
            else:
                import gzip
                import shutil
                fname = os.path.join(tmp_dir, 'file{0}'.format(i))
                with open(fname, 'rb') as f_in, \
                        gzip.open(fname + '.gz', 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                os.unlink(fname)
    return tmp_dir


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate random testing files for Snowflake')
    parser.add_argument('k', metavar='K', type=int,
                        help='number of lines to generate in each files')
    parser.add_argument('n', metavar='N', type=int,
                        help='number of files to generate')
    parser.add_argument('--dir', action='store', default=None,
                        help='the directory in which to generate files')
    args = vars(parser.parse_args())
    print(generate_k_lines_of_n_files(k=args['k'], n=args['n'], tmp_dir=args['dir']))
