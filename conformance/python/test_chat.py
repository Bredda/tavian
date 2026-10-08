import asyncio

from conftest import user


def test_chat_completion(client):
    resp = client.chat.completions.create(model="chat", messages=user("Say hello"))
    assert resp.object == "chat.completion"
    choice = resp.choices[0]
    assert choice.message.role == "assistant"
    assert choice.message.content == "mock reply to: Say hello"
    assert choice.finish_reason == "stop"
    assert resp.usage.prompt_tokens > 0
    assert resp.usage.completion_tokens > 0
    assert resp.usage.total_tokens == resp.usage.prompt_tokens + resp.usage.completion_tokens


def test_system_and_multipart_content(client):
    resp = client.chat.completions.create(
        model="chat",
        messages=[
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": [{"type": "text", "text": "Describe a cat"}]},
        ],
    )
    assert resp.choices[0].message.content == "mock reply to: Describe a cat"


def test_unknown_request_fields_reach_the_backend(client):
    # The mock reports the top-level fields it received in system_fingerprint.
    resp = client.chat.completions.create(
        model="chat",
        messages=user("hi"),
        temperature=0.2,
        max_tokens=16,
        seed=7,
        extra_body={"vendor_extension": {"a": 1}},
    )
    keys = resp.system_fingerprint.removeprefix("mock keys=").split(",")
    for expected in ("temperature", "max_tokens", "seed", "vendor_extension"):
        assert expected in keys, keys


def test_model_name_is_mapped_in_and_out(client):
    resp = client.chat.completions.create(model="chat", messages=user("hi"))
    # The backend was asked for its own name (the mock reports it)...
    assert resp.model_extra["x_mock_received_model"] == "mock"
    # ...but the client gets back the name it used.
    assert resp.model == "chat"


def test_request_id_header(client):
    raw = client.chat.completions.with_raw_response.create(model="chat", messages=user("hi"))
    assert raw.headers["x-request-id"]
    assert raw.parse().choices


def test_caller_request_id_is_kept(client):
    raw = client.chat.completions.with_raw_response.create(
        model="chat", messages=user("hi"), extra_headers={"X-Request-Id": "conformance-123"}
    )
    assert raw.headers["x-request-id"] == "conformance-123"


def test_async_client(make_async_client):
    async def go():
        async with make_async_client() as c:
            return await c.chat.completions.create(model="chat", messages=user("async"))

    resp = asyncio.run(go())
    assert resp.choices[0].message.content == "mock reply to: async"
