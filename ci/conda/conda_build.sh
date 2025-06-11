# Check https://snow-external.slack.com/archives/C02D68R4D0D/p1678899446863299 for context about using --numpy
conda install conda-build
conda install conda-verify
conda install diffutils
conda build recipe/ --python 3.9
conda build recipe/ --python 3.10
conda build recipe/ --python 3.11
conda build recipe/ --python 3.12
#conda build recipe/ --python=3.10 --numpy=1.21
#conda build recipe/ --python=3.11 --numpy=1.23
#conda build recipe/ --python=3.12 --numpy=1.26
