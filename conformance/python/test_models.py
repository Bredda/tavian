def test_list_models_returns_what_the_key_may_use(client):
    ids = {m.id for m in client.models.list()}
    assert ids == {"chat", "other", "broken"}


def test_list_models_is_filtered_per_key(narrow_client):
    assert [m.id for m in narrow_client.models.list()] == ["chat"]


def test_model_objects_are_well_formed(client):
    for m in client.models.list():
        assert m.object == "model"
        assert m.owned_by == "tavian"
        assert m.created > 0
