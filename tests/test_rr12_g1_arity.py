"""Round-12 G-1 witnesses: the arity bug class is dead.

The ba33b11 review caught run_correlation returning a 5-tuple on the
empty path while every caller unpacked 6 — every zero-anomaly run
crashed (the baseline week dies on chunk 1). The suite was blind
because test_empty asserted the OLD 5-value contract: the test was
built on the same misunderstanding as the bug (F9 disease, third
recurrence).

These witnesses close the class three ways:
  1. NO-MOCK pipeline witness: the REAL pipeline.correlation.run_correlation
     with anomalies=[] returns without raising (the fake client is a
     fixture for the block read, not a mock of the unit under test).
  2. AST guard: every return in nabla.correlation.run_correlation
     constructs a CorrelationOutput — a bare positional tuple return
     fails this witness.
  3. W-1 name-separation: CorrelationOutput (correlation step, shown_findings
     is a LIST) vs the pipeline's CorrelationResult (findings_shown is an
     int COUNT) — the round-8 same-name trap, asserted away.
"""
import ast
from pathlib import Path

from nabla.correlation import CorrelationOutput
from nabla.pipeline.correlation import CorrelationResult as PipelineCorrelationResult


class _FakeBlocks:
    """Minimal in-memory client for the block read/write — fixture,
    not a mock of the unit under test (run_correlation is fully real)."""

    def __init__(self, values):
        self._values = values
        self.updates = []

    def list(self, agent_id=None):
        class B:
            def __init__(self, label, value):
                self.label, self.value = label, value
        return [B(l, v) for l, v in self._values.items()]

    def update(self, agent_id=None, block_id=None, block_label=None, value=None):
        self.updates.append((block_label, value))
        self._values[block_label] = value


class _FakeAgents:
    def __init__(self, values):
        self.blocks = _FakeBlocks(values)


class _FakeClient:
    def __init__(self, values):
        self.agents = _FakeAgents(values)


class TestNoMockPipelineWitness:
    def test_zero_anomaly_run_through_the_real_pipeline(self):
        """THE G-1 regression: this exact call raised ValueError at
        ba33b11 (5-tuple vs 6-unpack). It must return a populated
        CorrelationResult with no findings."""
        from nabla.pipeline.correlation import run_correlation

        client = _FakeClient({"attack_mapping": ""})
        result = run_correlation(
            client=client,
            agents={"supervisor": "agent-test"},
            anomalies=[],
            graph_context_text="",
        )
        assert isinstance(result, PipelineCorrelationResult)
        assert result.findings_text == "Confirmed threats: none"
        assert result.findings == []
        assert result.findings_count == 0
        assert result.findings_shown == 0
        assert result.shown_keys == []


class TestAstArityGuard:
    def test_every_return_in_run_correlation_constructs_the_dataclass(self):
        """A bare positional tuple return anywhere in run_correlation
        reintroduces the G-1 bug class. Fail loudly on sight of one."""
        src = Path("nabla/correlation.py").read_text()
        tree = ast.parse(src)
        fn = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "run_correlation"
        )
        returns = [
            n for n in ast.walk(fn)
            if isinstance(n, ast.Return)
        ]
        assert returns, "run_correlation not found or has no returns"
        for ret in returns:
            is_output = (
                isinstance(ret.value, ast.Call)
                and isinstance(ret.value.func, ast.Name)
                and ret.value.func.id == "CorrelationOutput"
            )
            assert is_output, (
                f"run_correlation has a non-CorrelationOutput return at "
                f"line {ret.lineno} — positional returns are the G-1 bug class"
            )


class TestNameSeparation:
    """W-1: two classes, two names, two shapes — asserted so the
    round-8 same-name trap can't silently reappear."""

    def test_pipeline_result_count_is_int_and_output_list_is_list(self):
        import dataclasses
        out_fields = {f.name: f for f in dataclasses.fields(CorrelationOutput)}
        res_fields = {
            f.name: f for f in dataclasses.fields(PipelineCorrelationResult)
        }
        # the correlation step's shown list
        assert "shown_findings" in out_fields
        assert "findings_shown" not in out_fields, (
            "CorrelationOutput must NOT carry findings_shown — that name "
            "belongs to the pipeline result's int COUNT (W-1)"
        )
        # the pipeline result's count
        assert "findings_shown" in res_fields
        assert "shown_findings" not in res_fields

    def test_no_module_imports_both_under_one_name(self):
        """Nothing imports CorrelationOutput and the pipeline's
        CorrelationResult under the same local name."""
        for py in Path("nabla").rglob("*.py"):
            tree = ast.parse(py.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    names = [a.asname or a.name for a in node.names]
                    if "CorrelationOutput" in names and "CorrelationResult" in names:
                        raise AssertionError(
                            f"{py} imports both correlation classes — "
                            "the same-name trap"
                        )
