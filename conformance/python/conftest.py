import os

import pytest
from openai import AsyncOpenAI, OpenAI

BASE_URL = os.environ["TAVIAN_BASE_URL"]
KEY = os.environ["TAVIAN_KEY"]
NARROW_KEY = os.environ["TAVIAN_NARROW_KEY"]


@pytest.fixture
def client():
    # No retries: error tests must see the first answer, not the third.
    return OpenAI(base_url=BASE_URL, api_key=KEY, max_retries=0)


@pytest.fixture
def narrow_client():
    return OpenAI(base_url=BASE_URL, api_key=NARROW_KEY, max_retries=0)


@pytest.fixture
def make_async_client():
    return lambda: AsyncOpenAI(base_url=BASE_URL, api_key=KEY, max_retries=0)


def user(text):
    return [{"role": "user", "content": text}]


WEATHER_TOOL = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Get the weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
}
