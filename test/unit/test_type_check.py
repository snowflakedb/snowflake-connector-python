import snowflake.connector as conn

c = conn.connect(
    user="user",
    password="pass",
    account="account"
)

invalid = conn.connect(
    user="user",
    password=123, 
    account="account"
)
