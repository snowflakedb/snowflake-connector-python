## quick start for performance testing


### setup

note: you need to put your own credentials into parameters.py

```bash
git clone git@github.com:snowflakedb/snowflake-connector-python.git
cd snowflake-connector-python/test/stress
pip install -r dev_requirements.txt
touch parameters.py  # set your own connection parameters
```

### run unit perf test

This test will use the test dataset stored in the "stress_test_data" folder.
check the read me in the folder to see what datasets are available.

```python
python local_iterator.py
```

### run e2e perf test

This test will run query against snowflake. update the script to prepare the data and run the test.

```python
python e2e_iterator.py
```
