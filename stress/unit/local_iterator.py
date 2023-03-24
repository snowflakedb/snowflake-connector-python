import base64
import io

import stress.util as stress_util
from snowflake.connector.arrow_context import ArrowConverterContext
from snowflake.connector.arrow_iterator import PyArrowIterator
from stress.util import task_memory_decorator, task_time_execution_decorator

stress_util.print_to_console = False
can_draw = True
try:
    import matplotlib.pyplot as plt
except ImportError:
    can_draw = False

b64data = "<data>"
iteration_cnt = 100000
decoded_bytes = base64.b64decode(b64data)
arrow_context = ArrowConverterContext()


def task_for_loop_iterator(bytes_data):
    arrow_iter = PyArrowIterator(
        None,
        io.BytesIO(bytes_data),
        arrow_context,
        False,
        False,
        False,
    )
    for _ in arrow_iter:
        pass


def execute_task(task, bytes_data):
    for _ in range(iteration_cnt):
        task(bytes_data)


if __name__ == "__main__":

    perf_check_task_for_loop_iterator = task_time_execution_decorator(
        task_for_loop_iterator
    )
    memory_check_task_for_loop_iterator = task_memory_decorator(task_for_loop_iterator)

    execute_task(memory_check_task_for_loop_iterator, decoded_bytes)
    memory_records = stress_util.collect_memory_records()
    execute_task(perf_check_task_for_loop_iterator, decoded_bytes)
    time_records = stress_util.collect_time_execution_records()

    if can_draw:
        plt.plot([i for i in range(len(time_records))], time_records)
        plt.title("per iteration execution time")
        plt.show()
        plt.plot(
            [item[0] for item in memory_records], [item[1] for item in memory_records]
        )
        plt.title("memory usage")
        plt.show()
