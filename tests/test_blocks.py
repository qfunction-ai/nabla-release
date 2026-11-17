"""Tests for shared memory blocks."""

from unittest.mock import MagicMock, patch

from nabla.blocks import SHARED_BLOCKS, find_shared_blocks, get_or_create_shared_blocks


def test_shared_blocks_defined():
    """All expected shared blocks should be defined."""
    expected_labels = {"ingestion_status", "anomaly_queue", "threat_findings", "rl_thresholds", "attack_mapping", "lolbin_db", "graph_context", "environment_context", "system_phase"}
    assert set(SHARED_BLOCKS.keys()) == expected_labels


def test_rl_thresholds_includes_lolbin():
    """The rl_thresholds block should include lolbin_sensitivity."""
    text = SHARED_BLOCKS["rl_thresholds"]
    assert "lolbin_sensitivity" in text
    assert "0.7" in text


def test_attack_mapping_block_exists():
    """The attack_mapping block should exist with initial placeholder."""
    assert "attack_mapping" in SHARED_BLOCKS
    assert "ATT&CK" in SHARED_BLOCKS["attack_mapping"] or "not loaded" in SHARED_BLOCKS["attack_mapping"]


def test_lolbin_db_block_exists():
    """The lolbin_db block should exist with initial placeholder."""
    assert "lolbin_db" in SHARED_BLOCKS
    assert "LOLBIN" in SHARED_BLOCKS["lolbin_db"] or "not loaded" in SHARED_BLOCKS["lolbin_db"]


# ---------------------------------------------------------------------------
# find_shared_blocks
# ---------------------------------------------------------------------------

def test_find_shared_blocks_all_found():
    """When all blocks exist, find_shared_blocks returns {label: block_id}."""
    client = MagicMock()

    def fake_list(label, limit):
        block = MagicMock()
        block.id = f"existing-{label}"
        return [block]

    client.blocks.list.side_effect = fake_list

    result = find_shared_blocks(client)

    assert result is not None
    assert len(result) == len(SHARED_BLOCKS)
    for label in SHARED_BLOCKS:
        assert result[label] == f"existing-{label}"
    assert client.blocks.list.call_count == len(SHARED_BLOCKS)


def test_find_shared_blocks_partial_miss_returns_none():
    """When one block is missing from list results, find_shared_blocks returns None."""
    client = MagicMock()
    missing_label = "anomaly_queue"

    def fake_list(label, limit):
        if label == missing_label:
            return []  # block not found
        block = MagicMock()
        block.id = f"existing-{label}"
        return [block]

    client.blocks.list.side_effect = fake_list

    result = find_shared_blocks(client)

    assert result is None


def test_find_shared_blocks_empty_list_returns_none():
    """When client.blocks.list returns an empty list for the first block, returns None."""
    client = MagicMock()
    client.blocks.list.return_value = []

    result = find_shared_blocks(client)

    assert result is None


# ---------------------------------------------------------------------------
# get_or_create_shared_blocks
# ---------------------------------------------------------------------------

def test_get_or_create_all_exist():
    """When all blocks already exist, get_or_create returns them without creating new ones."""
    client = MagicMock()

    def fake_list(label, limit):
        block = MagicMock()
        block.id = f"existing-{label}"
        return [block]

    client.blocks.list.side_effect = fake_list

    result = get_or_create_shared_blocks(client)

    assert len(result) == len(SHARED_BLOCKS)
    for label in SHARED_BLOCKS:
        assert result[label] == f"existing-{label}"
    # No blocks should have been created
    client.blocks.create.assert_not_called()


def test_get_or_create_some_missing():
    """When some blocks are missing, get_or_create creates only the missing ones."""
    client = MagicMock()
    existing_labels = {"ingestion_status", "anomaly_queue", "threat_findings"}
    missing_labels = set(SHARED_BLOCKS.keys()) - existing_labels

    # Patch find_shared_blocks to return a partial dict (simulating partial find)
    with patch("nabla.blocks.find_shared_blocks") as mock_find:
        mock_find.return_value = {label: f"existing-{label}" for label in existing_labels}

        call_index = 0

        def fake_create(label, value):
            nonlocal call_index
            block = MagicMock()
            block.id = f"created-{label}-{call_index}"
            call_index += 1
            return block

        client.blocks.create.side_effect = fake_create

        result = get_or_create_shared_blocks(client)

    # Existing blocks should be in the result with their original ids
    for label in existing_labels:
        assert result[label] == f"existing-{label}"

    # Missing blocks should have been created
    assert client.blocks.create.call_count == len(missing_labels)
    for label in missing_labels:
        client.blocks.create.assert_any_call(label=label, value=SHARED_BLOCKS[label])
        assert result[label].startswith("created-")

    # Existing blocks should NOT have been created
    created_labels = {call.kwargs["label"] for call in client.blocks.create.call_args_list}
    for label in existing_labels:
        assert label not in created_labels, f"create was called for existing block '{label}'"


def test_get_or_create_none_existing():
    """When no blocks exist, get_or_create creates all of them."""
    client = MagicMock()

    # find_shared_blocks will return None because list returns empty
    client.blocks.list.return_value = []

    call_index = 0

    def fake_create(label, value):
        nonlocal call_index
        block = MagicMock()
        block.id = f"new-{label}-{call_index}"
        call_index += 1
        return block

    client.blocks.create.side_effect = fake_create

    result = get_or_create_shared_blocks(client)

    assert len(result) == len(SHARED_BLOCKS)
    assert client.blocks.create.call_count == len(SHARED_BLOCKS)
    for label, value in SHARED_BLOCKS.items():
        client.blocks.create.assert_any_call(label=label, value=value)
