|<img src="img/snowflake.png" width="400" /> | <img src="img/saturn.png" width="400" />|
| -- | -- |


# Using Snowflake with Saturn Cloud

[Snowflake](https://www.snowflake.com/) is a cloud-based data warehouse that allows for fast SQL queries. This example shows how to query data in Snowflake and pull into [Saturn Cloud](https://www.saturncloud.io/) for data science work. 

# Credentials and connecting

To avoid setting credentials directly in notebooks, we recommend uploading credentials stored a in .yml file on the "Credentials page" in Saturn Cloud.

- Type: `File`
- Shared with: `<your username>`
- Path: /home/jovyan/snowflake_creds.yml
- Value: .yml file contents (below)

The .yml file can specify any arguments that can be passed to `snowflake.connector.connect`, such as:

```yaml
account: ...
user: ...
password: ...
role: ...
```

You will need to restart the Jupyter server if you add a Credential while its running. Then from any notebook where you want to connect to Snowflake, you can read in the credentials file and then provide additional arguments (or override the ones set in the file):

```python
import yaml
import snowflake.connector

creds = yaml.full_load(open('/home/jovyan/snowflake_creds.yml'))
conn = snowflake.connector.connect(
    warehouse=...,
    database=...,
    schema=...,
    **creds,
)
```

# Loading data with Pandas

If your table or query result fits into the memory of your Jupyter client, you can load data into a pandas dataframe using `fetch_pandas_all()` or `fetch_pandas_batch()`.

See [`snowflake-pandas.ipynb`](snowflake-pandas.ipynb).

# Loading data with Dask

If your table or query result _don't_ into the memory of your Jupyter client, you can use Dask! Then you can take advantage of using a Dask cluster with Saturn to speed up your computations.

See [`snowflake-dask.ipynb`](snowflake-dask.ipynb).