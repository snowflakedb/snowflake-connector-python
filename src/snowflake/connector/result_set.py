#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#
from concurrent.futures import Future
from concurrent.futures.thread import ThreadPoolExecutor
from logging import getLogger
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    Union,
)

from .arrow_iterator import TABLE_UNIT
from .errors import NotSupportedError
from .options import installed_pandas, pandas
from .result_batch import ArrowResultBatch, DownloadMetrics, ResultBatch
from .telemetry import TelemetryField
from .time_util import get_time_millis

if TYPE_CHECKING:  # pragma: no cover
    from snowflake.connector.cursor import SnowflakeCursor

if installed_pandas:
    from pyarrow import Table, concat_tables
else:
    Table = None

logger = getLogger(__name__)


def result_set_iterator(
    pre_iter: Iterator[Iterator[Tuple]],
    post_iter: Iterable["ResultBatch"],
    final: Callable[[], None],
    **kw: Any,
) -> Union[
    Iterator[Union[Dict, Exception]],
    Iterator[Union[Tuple, Exception]],
    Iterator[Table],
]:
    """Creates an iterator over some other iterators.

    Very similar to itertools.chain but we need some keywords to be propagated to
    `_download` functions later.

    We need this to have ResultChunks fall out of usage so that they can be garbage
    collected.

    Just like `ResultBatch` iterator, this might yield an `Exception` to allow users to
    continue iterating through the rest of the `ResultBatch`.
    """
    for it in pre_iter:
        for element in it:
            yield element
    for it in post_iter:
        for element in it._download(**kw):
            yield element
    final()


class ResultSet(Iterable[List[Any]]):
    """This class retrieves the results of a query with the historical strategy.

    It pre-downloads the first up to 4 ResultChunks (this doesn't include the 1st chunk
    as that is embedded in the response JSON from Snowflake) upon creating an Iterator
    on it.

    It also reports telemetry data about its `ResultBatch`es once it's done iterating
    through them.
    """

    def __init__(
        self,
        cursor: "SnowflakeCursor",
        result_chunks: List["ResultBatch"],
    ):
        self.batches = result_chunks
        self._cursor = cursor
        self._iter: Optional[Iterator[Tuple]] = None

    def _report_metrics(self) -> None:
        """Report all metrics totalled up.

        This includes TIME_CONSUME_LAST_RESULT, TIME_DOWNLOADING_CHUNKS and
        TIME_PARSING_CHUNKS in that order.
        """
        time_consume_last_result = get_time_millis() - self._cursor._first_chunk_time
        self._cursor._log_telemetry_job_data(
            TelemetryField.TIME_CONSUME_LAST_RESULT, time_consume_last_result
        )
        metrics = self._get_metrics()
        if DownloadMetrics.download.value in metrics:
            self._cursor._log_telemetry_job_data(
                TelemetryField.TIME_DOWNLOADING_CHUNKS,
                metrics.get(DownloadMetrics.download.value),
            )
        if DownloadMetrics.parse.value in metrics:
            self._cursor._log_telemetry_job_data(
                TelemetryField.TIME_PARSING_CHUNKS,
                metrics.get(DownloadMetrics.parse.value),
            )

    def _fetch_arrow_batches(
        self,
    ) -> Iterator[Table]:
        """Fetches a all the results as Arrow Tables, chunked by Snowflake back-end."""
        # For now we don't support mixed ResultSets, so assume first partition's type
        #  represents them all
        head_type = type(self.batches[0])
        if head_type != ArrowResultBatch:
            raise NotSupportedError(
                f"Trying to use arrow fetching on {head_type} which "
                f"is not ArrowResultChunk"
            )
        return self._create_iter(iter_unit=TABLE_UNIT)

    def _fetch_arrow_all(self):
        """Fetches a single Arrow Table from all of the `ResultBatch`."""
        tables = list(self._fetch_arrow_batches())
        if tables:
            return concat_tables(tables)
        else:
            return None

    def _fetch_pandas_batches(self, **kwargs):
        """Fetches Pandas dataframes in batches, where batch refers to Snowflake Chunk.

        Thus, the batch size (the number of rows in dataframe) is determined by
        Snowflake's back-end.
        """
        for table in self._fetch_arrow_batches():
            yield table.to_pandas(**kwargs)

    def _fetch_pandas_all(self, **kwargs):
        """Fetches a single Pandas dataframe."""
        table = self._fetch_arrow_all()
        if table:
            return table.to_pandas(**kwargs)
        else:
            return pandas.DataFrame(columns=self.batches[0]._column_names)

    def _get_metrics(self) -> Dict[str, int]:
        """Sum up all the chunks' metrics and show them together."""
        overall_metrics: Dict[str, int] = {}
        for c in self.batches:
            for n, v in c._metrics.items():
                overall_metrics[n] = overall_metrics.get(n, 0) + v
        return overall_metrics

    def __iter__(self) -> Iterator[Tuple]:
        """Returns a new iterator through all batches with default values."""
        return self._create_iter()

    def _create_iter(
        self,
        **kwargs,
    ) -> Union[
        Iterator[Union[Dict, Exception]],
        Iterator[Union[Tuple, Exception]],
        Iterator[Table],
    ]:
        """Set up a new iterator through all batches with first 5 chunks downloaded.

        This function is a helper function to `__iter__` and it was introduced for the
        cases where we need to propagate some values to later `_download` calls.
        """
        futures: List[Future[Iterator[Tuple]]] = []
        with ThreadPoolExecutor(4) as pool:
            for p in self.batches[1:5]:
                futures.append(pool.submit(p._download, **kwargs))
        pre_downloaded_iters: List[Iterator[Tuple]] = [
            self.batches[0]._download(**kwargs)
        ] + [r.result() for r in futures]
        post_download_iters = self.batches[5:]

        return result_set_iterator(
            iter(pre_downloaded_iters),
            iter(post_download_iters),
            self._report_metrics,
            **kwargs,
        )

    @property
    def total_row_index(self) -> int:
        """Returns the total rowcount of the `ResultSet` ."""
        total = 0
        for p in self.batches:
            total += p.rowcount
        return total
