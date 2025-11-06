# Check https://snow-external.slack.com/archives/C02D68R4D0D/p1678899446863299 for context about using --numpy
conda install conda-build
conda install conda-verify
conda install diffutils
conda build ci/anaconda/recipe/ --python 3.9
conda build ci/anaconda/recipe/ --python 3.10
conda build ci/anaconda/recipe/ --python 3.11
conda build ci/anaconda/recipe/ --python 3.12
conda build ci/anaconda/recipe/ --python 3.13
