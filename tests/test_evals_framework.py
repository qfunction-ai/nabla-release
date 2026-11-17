"""Tests for nabla.evals.framework — lightweight eval framework."""

import asyncio
import pytest

from nabla.evals.framework import (
    CheckStatus,
    FnCheck,
    LLMJudge,
    NotStringMatching,
    Scenario,
    ScenarioResult,
    StringMatching,
    Suite,
    SuiteResult,
    Trace,
    Interaction,
)


# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------

class TestTrace:
    def test_add_and_last(self):
        trace = Trace()
        trace.add("hello", "world")
        trace.add("foo", "bar")
        assert trace.last.inputs == "foo"
        assert trace.last.outputs == "bar"

    def test_empty_trace_raises(self):
        trace = Trace()
        with pytest.raises(IndexError):
            _ = trace.last

    def test_interactions_count(self):
        trace = Trace()
        trace.add("a", "b")
        trace.add("c", "d")
        assert len(trace.interactions) == 2


# ---------------------------------------------------------------------------
# FnCheck
# ---------------------------------------------------------------------------

class TestFnCheck:
    def test_passes(self):
        trace = Trace()
        trace.add("input", "output")
        check = FnCheck(fn=lambda t: "output" in str(t.last.outputs), name="has_output")
        result = check.evaluate(trace)
        assert result.passed
        assert result.status == CheckStatus.PASSED

    def test_fails(self):
        trace = Trace()
        trace.add("input", "output")
        check = FnCheck(fn=lambda t: "missing" in str(t.last.outputs), name="has_missing")
        result = check.evaluate(trace)
        assert not result.passed
        assert result.status == CheckStatus.FAILED

    def test_exception_handled(self):
        trace = Trace()
        trace.add("input", "output")
        check = FnCheck(fn=lambda t: 1 / 0, name="div_zero")
        result = check.evaluate(trace)
        assert result.status == CheckStatus.ERROR
        assert "ZeroDivisionError" in result.message

    def test_custom_messages(self):
        trace = Trace()
        trace.add("input", "output")
        check = FnCheck(
            fn=lambda t: True,
            name="with_messages",
            success_message="All good",
            failure_message="Something broke",
        )
        result = check.evaluate(trace)
        assert result.message == "All good"


# ---------------------------------------------------------------------------
# StringMatching
# ---------------------------------------------------------------------------

class TestStringMatching:
    def test_found(self):
        trace = Trace()
        trace.add("input", "The admin_svc account was compromised")
        check = StringMatching(name="finds_admin", keyword="admin_svc")
        result = check.evaluate(trace)
        assert result.passed

    def test_not_found(self):
        trace = Trace()
        trace.add("input", "Some unrelated text")
        check = StringMatching(name="finds_admin", keyword="admin_svc")
        result = check.evaluate(trace)
        assert not result.passed

    def test_case_insensitive(self):
        trace = Trace()
        trace.add("input", "ADMIN_SVC was detected")
        check = StringMatching(name="finds_admin", keyword="admin_svc", case_sensitive=False)
        result = check.evaluate(trace)
        assert result.passed

    def test_case_sensitive_miss(self):
        trace = Trace()
        trace.add("input", "ADMIN_SVC was detected")
        check = StringMatching(name="finds_admin", keyword="admin_svc", case_sensitive=True)
        result = check.evaluate(trace)
        assert not result.passed


# ---------------------------------------------------------------------------
# NotStringMatching
# ---------------------------------------------------------------------------

class TestNotStringMatching:
    def test_keyword_absent(self):
        trace = Trace()
        trace.add("input", "The findings are concerning")
        check = NotStringMatching(name="no_no_threats", keyword="no threats detected")
        result = check.evaluate(trace)
        assert result.passed

    def test_keyword_present(self):
        trace = Trace()
        trace.add("input", "There are no threats detected in this system")
        check = NotStringMatching(name="no_no_threats", keyword="no threats detected")
        result = check.evaluate(trace)
        assert not result.passed


# ---------------------------------------------------------------------------
# LLMJudge
# ---------------------------------------------------------------------------

class TestLLMJudge:
    def test_no_judge_fn(self):
        trace = Trace()
        trace.add("input", "output")
        check = LLMJudge(name="no_fn", judge_prompt="Is this good? {outputs}")
        result = check.evaluate(trace)
        assert result.status == CheckStatus.ERROR

    def test_judge_passes(self):
        trace = Trace()
        trace.add("input", "output")
        check = LLMJudge(
            name="judge_pass",
            judge_prompt="Evaluate: {outputs}",
            judge_fn=lambda prompt: "The result is passed: true",
        )
        result = check.evaluate(trace)
        assert result.passed

    def test_judge_fails(self):
        trace = Trace()
        trace.add("input", "output")
        check = LLMJudge(
            name="judge_fail",
            judge_prompt="Evaluate: {outputs}",
            judge_fn=lambda prompt: "The result is passed: false",
        )
        result = check.evaluate(trace)
        assert not result.passed

    def test_judge_ambiguous(self):
        trace = Trace()
        trace.add("input", "output")
        check = LLMJudge(
            name="judge_ambiguous",
            judge_prompt="Evaluate: {outputs}",
            judge_fn=lambda prompt: "I can't determine the answer",
        )
        result = check.evaluate(trace)
        assert result.status == CheckStatus.FAILED

    def test_judge_exception(self):
        trace = Trace()
        trace.add("input", "output")
        check = LLMJudge(
            name="judge_error",
            judge_prompt="Evaluate: {outputs}",
            judge_fn=lambda prompt: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        result = check.evaluate(trace)
        assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

class TestScenario:
    def test_single_interaction_and_check(self):
        scenario = (
            Scenario("simple_test")
            .interact(inputs="hello", outputs_fn=lambda x: f"echo: {x}")
            .check(FnCheck(fn=lambda t: "echo" in t.last.outputs, name="has_echo"))
        )
        result = asyncio.run(scenario.run())
        assert result.passed

    def test_multiple_checks(self):
        scenario = (
            Scenario("multi_check")
            .interact(inputs="test", outputs_fn=lambda x: "admin_svc compromised")
            .check(StringMatching(name="finds_admin", keyword="admin_svc"))
            .check(StringMatching(name="finds_compromised", keyword="compromised"))
        )
        result = asyncio.run(scenario.run())
        assert result.passed

    def test_failing_check(self):
        scenario = (
            Scenario("fail_test")
            .interact(inputs="test", outputs_fn=lambda x: "nothing interesting")
            .check(StringMatching(name="finds_admin", keyword="admin_svc"))
        )
        result = asyncio.run(scenario.run())
        assert not result.passed

    def test_no_outputs_fn(self):
        scenario = (
            Scenario("no_fn")
            .interact(inputs="test")
            .check(FnCheck(fn=lambda t: True, name="always_pass"))
        )
        result = asyncio.run(scenario.run())
        assert not result.passed  # Should error because no outputs_fn

    def test_target_function(self):
        """Test using Suite.run(target=...) to provide the SUT."""
        scenario = (
            Scenario("with_target")
            .interact(inputs="hello")
            .check(FnCheck(fn=lambda t: "echo" in t.last.outputs, name="has_echo"))
        )
        result = asyncio.run(scenario.run(target=lambda x: f"echo: {x}"))
        assert result.passed

    def test_print_report(self, capsys):
        scenario = (
            Scenario("report_test")
            .interact(inputs="test", outputs_fn=lambda x: "output")
            .check(FnCheck(fn=lambda t: True, name="passing"))
        )
        result = asyncio.run(scenario.run())
        result.print_report()
        captured = capsys.readouterr()
        assert "PASSED" in captured.out

    def test_result_serialization(self):
        scenario = (
            Scenario("serial_test")
            .interact(inputs="test", outputs_fn=lambda x: "output")
            .check(FnCheck(fn=lambda t: True, name="passing"))
        )
        result = asyncio.run(scenario.run())
        d = result.to_dict()
        assert d["name"] == "serial_test"
        assert d["passed"] is True
        assert len(d["checks"]) == 1


# ---------------------------------------------------------------------------
# Suite
# ---------------------------------------------------------------------------

class TestSuite:
    def test_multiple_scenarios(self):
        suite = Suite("test_suite")
        suite.add(
            Scenario("passing")
            .interact(inputs="a", outputs_fn=lambda x: "admin_svc")
            .check(StringMatching(name="finds_admin", keyword="admin_svc"))
        )
        suite.add(
            Scenario("also_passing")
            .interact(inputs="b", outputs_fn=lambda x: "certutil detected")
            .check(StringMatching(name="finds_certutil", keyword="certutil"))
        )
        result = asyncio.run(suite.run())
        assert result.passed
        assert result.pass_rate == 1.0

    def test_mixed_results(self):
        suite = Suite("mixed_suite")
        suite.add(
            Scenario("passing")
            .interact(inputs="a", outputs_fn=lambda x: "admin_svc")
            .check(StringMatching(name="finds_admin", keyword="admin_svc"))
        )
        suite.add(
            Scenario("failing")
            .interact(inputs="b", outputs_fn=lambda x: "nothing")
            .check(StringMatching(name="finds_admin", keyword="admin_svc"))
        )
        result = asyncio.run(suite.run())
        assert not result.passed
        assert result.pass_rate == 0.5

    def test_print_report(self, capsys):
        suite = Suite("report_suite")
        suite.add(
            Scenario("passing")
            .interact(inputs="a", outputs_fn=lambda x: "admin_svc")
            .check(StringMatching(name="finds_admin", keyword="admin_svc"))
        )
        result = asyncio.run(suite.run())
        result.print_report()
        captured = capsys.readouterr()
        assert "100%" in captured.out

    def test_to_json(self):
        suite = Suite("json_suite")
        suite.add(
            Scenario("passing")
            .interact(inputs="a", outputs_fn=lambda x: "admin_svc")
            .check(StringMatching(name="finds_admin", keyword="admin_svc"))
        )
        result = asyncio.run(suite.run())
        json_str = result.to_json()
        assert '"passed": true' in json_str or '"passed":true' in json_str
