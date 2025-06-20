import pytest

from ..http_test_utils import DynamicCollectingCustomizer, StaticCollectingCustomizer


@pytest.fixture
def static_collecting_customizer():
    return StaticCollectingCustomizer()


@pytest.fixture
def dynamic_collecting_customizer():
    return DynamicCollectingCustomizer()
