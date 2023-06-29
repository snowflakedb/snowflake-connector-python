# Contributing to snowflake-connector-python

Hi, thank you for taking the time to improve Snowflake's Python connector!

## I have a feature request, or a bug report to submit

Many questions can be answered by checking our [docs](https://docs.snowflake.com/) or looking for already existing bug reports and enhancement requests on our [issue tracker](https://github.com/snowflakedb/snowflake-connector-python/issues).

Please start by checking these first!

## Nobody else had my idea/issue

In that case we'd love to hear from you!
Please [open a new issue](https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose) to get in touch with us.

## I'd like to contribute the bug fix or feature myself

We encourage everyone to first open an issue to discuss any feature work or bug fixes with one of the maintainers.
This should help guide contributors through potential pitfalls.

## Contributor License Agreement ("CLA")

We require our contributors to sign a CLA, available at https://github.com/snowflakedb/CLA/blob/main/README.md. A Github Actions bot will assist you when you open a pull request.

### Setup a development environment

What is a development environment? It's a [virtualenv](https://virtualenv.pypa.io) that has all of necessary
dependencies installed with `snowflake-connector-python` installed as an editable package.

Setting up a development environment is super easy with this [one simple tox command](https://tox.wiki/en/latest/example/devenv.html).

```shell
tox --devenv venv37 -e py37
. venv37/bin/activate
```

Note: we suggest using the lowest supported Python version for development.

To run tests, please see our [testing README](test/README.md).
