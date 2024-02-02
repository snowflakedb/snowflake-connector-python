# Test Data Description

## test_data_all_types

This dataset contains 1 batch, 100 rows of data,  and the schema of the data contains 27 columns.

### sample row data:

```python
(
    123456,
    bytearray(b'HELP'),
    True,
    'a',
    'b',
    datetime.date(2023, 7, 18),
    datetime.datetime(2023, 7, 18, 12, 51),
    Decimal('984.280'),
    Decimal('268.350'),
    123.456,
    738.132,
    6789,
    23456,
    12583,
    513.431,
    10,
    9,
    'fjisfsj',
    'wkdoajde131',
    datetime.time(12, 34, 56),
    datetime.datetime(2021, 1, 1, 0, 0),
    datetime.datetime(2021, 1, 1, 0, 0, tzinfo=<UTC>),
    datetime.datetime(2020, 12, 31, 16, 0, tzinfo=<DstTzInfo 'America/Los_Angeles' PST-1 day, 16:00:00 STD>),
    datetime.datetime(2021, 1, 1, 0, 0),
    1,
    bytearray(b'HELP'),
    'vxlmls!21321#@!#!'
)
```

## test_multi_column_row_decimal_data

This dataset contains 9 batches, each batch has approximately ~1700 rows of data, and the schema of the data contains 19 columns.

### sample row data:
```python
(
    datetime.date(2021, 1, 3),
    8371,
    'segment_no_0',
    1,
    7,
    2,
    Decimal('0.285714'),
    Decimal('1.000'),
    Decimal('7.000'),
    Decimal('2.000'),
    Decimal('0.285714000'),
    Decimal('1.000'),
    Decimal('7.000'),
    Decimal('2.000'),
    Decimal('0.285714000'),
    Decimal('1.000'),
    Decimal('7.000'),
    Decimal('2.000'),
    Decimal('0.285714000')
)
```
