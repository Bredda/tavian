import json

from conftest import WEATHER_TOOL, user


def test_tool_call(client):
    resp = client.chat.completions.create(model="chat", messages=user("Paris?"), tools=[WEATHER_TOOL])
    choice = resp.choices[0]
    assert choice.finish_reason == "tool_calls"
    assert choice.message.content is None
    (call,) = choice.message.tool_calls
    assert call.type == "function"
    assert call.function.name == "get_weather"
    assert json.loads(call.function.arguments) == {"echo": "Paris?"}


def test_tool_round_trip(client):
    first = client.chat.completions.create(model="chat", messages=user("Paris?"), tools=[WEATHER_TOOL])
    call = first.choices[0].message.tool_calls[0]
    followup = client.chat.completions.create(
        model="chat",
        tools=[WEATHER_TOOL],
        messages=[
            *user("Paris?"),
            first.choices[0].message.model_dump(exclude_none=True),
            {"role": "tool", "tool_call_id": call.id, "content": "sunny"},
        ],
    )
    assert followup.choices[0].finish_reason == "stop"
    assert "sunny" in followup.choices[0].message.content


def test_tool_choice_none_is_respected(client):
    resp = client.chat.completions.create(
        model="chat", messages=user("Paris?"), tools=[WEATHER_TOOL], tool_choice="none"
    )
    assert resp.choices[0].finish_reason == "stop"
    assert not resp.choices[0].message.tool_calls


def test_streamed_tool_call_with_the_stream_helper(client):
    with client.chat.completions.stream(model="chat", messages=user("Paris?"), tools=[WEATHER_TOOL]) as stream:
        final = stream.get_final_completion()
    choice = final.choices[0]
    assert choice.finish_reason == "tool_calls"
    (call,) = choice.message.tool_calls
    assert call.function.name == "get_weather"
    assert json.loads(call.function.arguments) == {"echo": "Paris?"}


def test_streamed_tool_call_assembled_by_hand(client):
    stream = client.chat.completions.create(
        model="chat", messages=user("Paris?"), tools=[WEATHER_TOOL], stream=True
    )
    name, args, finish = "", "", None
    for chunk in stream:
        if not chunk.choices:
            continue
        c = chunk.choices[0]
        for tc in c.delta.tool_calls or []:
            name += tc.function.name or ""
            args += tc.function.arguments or ""
        finish = c.finish_reason or finish
    assert (name, finish) == ("get_weather", "tool_calls")
    assert json.loads(args) == {"echo": "Paris?"}
