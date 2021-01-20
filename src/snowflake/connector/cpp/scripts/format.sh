#!/bin/bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

find $THIS_DIR/.. -iname *.h -o -iname *.c -o -iname *.cpp -o -iname *.hpp \
    | xargs clang-format -style=file -i

exit 0
