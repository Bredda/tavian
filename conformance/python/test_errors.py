import openai
import pytest

from conftest import BASE_URL, user


def test_wrong_key_is_401(client):
    bad = openai.OpenAI(base_url=BASE_URL, api_key="tav_not-a-real-key", max_retries=0)
    with pytest.raises(openai.AuthenticationError) as e:
        bad.chat.completions.create(model="chat", messages=user("hi"))
    assert e.value.status_code == 401
    assert e.value.code == "invalid_api_key"


def test_model_outside_the_allow_list_is_403(narrow_client):
    with pytest.raises(openai.PermissionDeniedError) as e:
        narrow_client.chat.completions.create(model="other", messages=user("hi"))
    assert e.value.code == "model_not_allowed"


def test_allowed_but_unconfigured_model_is_404(client):
    with pytest.raises(openai.NotFoundError) as e:
        client.chat.completions.create(model="ghost-model", messages=user("hi"))
    assert e.value.status_code == 404
    assert e.value.code == "model_not_found"


def test_models_outside_the_allow_list_do_not_reveal_whether_they_exist(narrow_client):
    for name in ("other", "does-not-exist"):
        with pytest.raises(openai.PermissionDeniedError):
            narrow_client.chat.completions.create(model=name, messages=user("hi"))


def test_missing_model_is_400(client):
    with pytest.raises(openai.BadRequestError) as e:
        client.post("/chat/completions", body={"messages": user("hi")}, cast_to=object)
    assert e.value.code == "invalid_request"


def test_backend_error_is_relayed_as_a_server_error(client):
    with pytest.raises(openai.InternalServerError) as e:
        client.chat.completions.create(model="broken", messages=user("hi"))
    assert e.value.status_code == 500


def test_error_bodies_are_openai_shaped(client):
    with pytest.raises(openai.NotFoundError) as e:
        client.chat.completions.create(model="ghost-model", messages=user("hi"))
    err = e.value.body
    assert isinstance(err, dict) and err["type"] == "invalid_request_error" and err["message"]


def test_unsupported_endpoint_is_a_json_404(client):
    with pytest.raises(openai.NotFoundError) as e:
        client.embeddings.create(model="chat", input="hello")
    assert e.value.code == "not_found"
