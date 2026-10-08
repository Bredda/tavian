import asyncio

from conftest import user


def collect(stream):
    chunks = list(stream)
    text = "".join(c.choices[0].delta.content or "" for c in chunks if c.choices)
    return chunks, text


def test_stream_assembles_the_same_text(client):
    chunks, text = collect(client.chat.completions.create(model="chat", messages=user("Count"), stream=True))
    assert text == "mock reply to: Count"
    assert len(chunks) > 3  # really streamed, not one buffered blob
    assert chunks[0].choices[0].delta.role == "assistant"
    assert [c.choices[0].finish_reason for c in chunks if c.choices][-1] == "stop"


def test_every_chunk_carries_the_clients_model_name(client):
    chunks, _ = collect(client.chat.completions.create(model="chat", messages=user("Count"), stream=True))
    assert {c.model for c in chunks} == {"chat"}


def test_usage_chunk_when_requested(client):
    chunks, _ = collect(
        client.chat.completions.create(
            model="chat", messages=user("Count"), stream=True, stream_options={"include_usage": True}
        )
    )
    last = chunks[-1]
    assert last.choices == []
    assert last.usage.total_tokens > 0


def test_stream_works_without_asking_for_usage(client):
    # Tavian forces usage reporting upstream to meter streams; the extra final
    # chunk it relays must not trip the SDK.
    chunks, text = collect(client.chat.completions.create(model="chat", messages=user("Count"), stream=True))
    assert text == "mock reply to: Count"
    assert chunks[-1].choices == [] and chunks[-1].usage.total_tokens > 0


def test_stream_helper_builds_the_final_completion(client):
    with client.chat.completions.stream(model="chat", messages=user("Helper")) as stream:
        final = stream.get_final_completion()
    assert final.choices[0].message.content == "mock reply to: Helper"
    assert final.choices[0].finish_reason == "stop"


def test_early_close_leaves_the_gateway_usable(client):
    stream = client.chat.completions.create(model="chat", messages=user("Count"), stream=True)
    next(iter(stream))
    stream.close()
    resp = client.chat.completions.create(model="chat", messages=user("after"))
    assert resp.choices[0].message.content == "mock reply to: after"


def test_async_stream(make_async_client):
    async def go():
        async with make_async_client() as c:
            stream = await c.chat.completions.create(model="chat", messages=user("Async"), stream=True)
            return [chunk async for chunk in stream]

    chunks = asyncio.run(go())
    text = "".join(c.choices[0].delta.content or "" for c in chunks if c.choices)
    assert text == "mock reply to: Async"
