"""Lightweight evaluation framework for non-deterministic AI systems.

Borrows the design patterns from Giskard v3 (Scenario, Trace, Check, Suite)
but has zero external dependencies. Scenarios written against this API
transfer directly to giskard-checks when Python 3.12+ is available.

Architecture:
- Scenario: named multi-turn interaction with checks
- Trace: captures inputs/outputs per turn
- Check: pass/fail assertion (deterministic or LLM-as-judge)
- Suite: compose scenarios, run all, get a report
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Check result
# ---------------------------------------------------------------------------

class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


@dataclass
class CheckResult:
    """Result of a single check evaluation."""
    name: str
    status: CheckStatus
    message: str = ""
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.status == CheckStatus.PASSED

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration_ms": round(self.duration_ms, 1),
        }


# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------

@dataclass
class Interaction:
    """A single interaction (input → output)."""
    inputs: Any
    outputs: Any
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "inputs": self.inputs if not isinstance(self.inputs, (dict, list)) else str(self.inputs),
            "outputs": self.outputs if isinstance(self.outputs, str) else str(self.outputs)[:500],
            "timestamp": self.timestamp,
        }


@dataclass
class Trace:
    """Captured interaction history across all turns of a scenario."""
    interactions: list[Interaction] = field(default_factory=list)

    @property
    def last(self) -> Interaction:
        """Get the most recent interaction."""
        if not self.interactions:
            raise IndexError("Trace has no interactions")
        return self.interactions[-1]

    def add(self, inputs: Any, outputs: Any) -> None:
        """Record a new interaction."""
        self.interactions.append(
            Interaction(
                inputs=inputs,
                outputs=outputs,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

class Check:
    """Base class for all checks."""
    def __init__(self, name: str) -> None:
        self.name = name

    def evaluate(self, trace: Trace) -> CheckResult:
        raise NotImplementedError


class FnCheck(Check):
    """Deterministic function-based check.

    The function receives a Trace and returns True (pass) or False (fail).
    """
    def __init__(
        self,
        fn: Callable[[Trace], bool],
        name: str,
        success_message: str = "",
        failure_message: str = "",
    ) -> None:
        super().__init__(name)
        self.fn = fn
        self.success_message = success_message
        self.failure_message = failure_message

    def evaluate(self, trace: Trace) -> CheckResult:
        t0 = time.monotonic()
        try:
            result = self.fn(trace)
            duration = (time.monotonic() - t0) * 1000
            if result:
                return CheckResult(
                    name=self.name,
                    status=CheckStatus.PASSED,
                    message=self.success_message or f"Check '{self.name}' passed",
                    duration_ms=duration,
                )
            return CheckResult(
                name=self.name,
                status=CheckStatus.FAILED,
                message=self.failure_message or f"Check '{self.name}' failed",
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.monotonic() - t0) * 1000
            return CheckResult(
                name=self.name,
                status=CheckStatus.ERROR,
                message=f"Check '{self.name}' raised {type(e).__name__}: {e}",
                duration_ms=duration,
            )


class StringMatching(Check):
    """Check that a keyword appears in the trace output."""
    def __init__(
        self,
        name: str,
        keyword: str,
        text_key: str = "trace.last.outputs",
        case_sensitive: bool = False,
    ) -> None:
        super().__init__(name)
        self.keyword = keyword
        self.text_key = text_key
        self.case_sensitive = case_sensitive

    def _extract_text(self, trace: Trace) -> str:
        """Extract text from trace using the key path."""
        if self.text_key == "trace.last.outputs":
            text = str(trace.last.outputs)
        elif self.text_key == "trace.last.inputs":
            text = str(trace.last.inputs)
        else:
            text = str(trace.last.outputs)
        return text if self.case_sensitive else text.lower()

    def evaluate(self, trace: Trace) -> CheckResult:
        t0 = time.monotonic()
        try:
            text = self._extract_text(trace)
            keyword = self.keyword if self.case_sensitive else self.keyword.lower()
            duration = (time.monotonic() - t0) * 1000
            if keyword in text:
                return CheckResult(
                    name=self.name,
                    status=CheckStatus.PASSED,
                    message=f"Found '{self.keyword}' in output",
                    duration_ms=duration,
                )
            return CheckResult(
                name=self.name,
                status=CheckStatus.FAILED,
                message=f"Did not find '{self.keyword}' in output",
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.monotonic() - t0) * 1000
            return CheckResult(
                name=self.name,
                status=CheckStatus.ERROR,
                message=f"StringMatching '{self.name}' raised {type(e).__name__}: {e}",
                duration_ms=duration,
            )


class NotStringMatching(Check):
    """Check that a keyword does NOT appear in the trace output."""
    def __init__(
        self,
        name: str,
        keyword: str,
        text_key: str = "trace.last.outputs",
        case_sensitive: bool = False,
    ) -> None:
        super().__init__(name)
        self.keyword = keyword
        self.text_key = text_key
        self.case_sensitive = case_sensitive

    def evaluate(self, trace: Trace) -> CheckResult:
        t0 = time.monotonic()
        try:
            if self.text_key == "trace.last.outputs":
                text = str(trace.last.outputs)
            else:
                text = str(trace.last.outputs)
            text = text if self.case_sensitive else text.lower()
            keyword = self.keyword if self.case_sensitive else self.keyword.lower()
            duration = (time.monotonic() - t0) * 1000
            if keyword not in text:
                return CheckResult(
                    name=self.name,
                    status=CheckStatus.PASSED,
                    message=f"Correctly did not find '{self.keyword}' in output",
                    duration_ms=duration,
                )
            return CheckResult(
                name=self.name,
                status=CheckStatus.FAILED,
                message=f"Incorrectly found '{self.keyword}' in output",
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.monotonic() - t0) * 1000
            return CheckResult(
                name=self.name,
                status=CheckStatus.ERROR,
                message=f"NotStringMatching '{self.name}' raised {type(e).__name__}: {e}",
                duration_ms=duration,
            )


class LLMJudge(Check):
    """LLM-as-judge check — evaluates the output using a separate LLM call.

    The judge_prompt is a format string with access to:
    - {inputs}: the last interaction's inputs
    - {outputs}: the last interaction's outputs
    - {trace}: the full trace object

    The judge should return text containing 'passed: true' or 'passed: false'.
    """
    def __init__(
        self,
        name: str,
        judge_prompt: str,
        judge_fn: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(name)
        self.judge_prompt = judge_prompt
        self.judge_fn = judge_fn

    def evaluate(self, trace: Trace) -> CheckResult:
        t0 = time.monotonic()
        if self.judge_fn is None:
            duration = (time.monotonic() - t0) * 1000
            return CheckResult(
                name=self.name,
                status=CheckStatus.ERROR,
                message=f"LLMJudge '{self.name}' has no judge_fn configured",
                duration_ms=duration,
            )

        try:
            # Format the prompt with trace data
            prompt = self.judge_prompt.format(
                inputs=trace.last.inputs,
                outputs=trace.last.outputs,
                trace=trace,
            )
            response = self.judge_fn(prompt)
            duration = (time.monotonic() - t0) * 1000

            # Parse the response for passed/failed
            response_lower = response.lower()
            if "passed: true" in response_lower or "passed:true" in response_lower:
                return CheckResult(
                    name=self.name,
                    status=CheckStatus.PASSED,
                    message=f"LLMJudge passed: {response[:200]}",
                    duration_ms=duration,
                )
            if "passed: false" in response_lower or "passed:false" in response_lower:
                return CheckResult(
                    name=self.name,
                    status=CheckStatus.FAILED,
                    message=f"LLMJudge failed: {response[:200]}",
                    duration_ms=duration,
                )
            # Fallback: if neither pattern found, fail
            return CheckResult(
                name=self.name,
                status=CheckStatus.FAILED,
                message=f"LLMJudge returned ambiguous result: {response[:200]}",
                duration_ms=duration,
            )
        except Exception as e:
            duration = (time.monotonic() - t0) * 1000
            return CheckResult(
                name=self.name,
                status=CheckStatus.ERROR,
                message=f"LLMJudge '{self.name}' raised {type(e).__name__}: {e}",
                duration_ms=duration,
            )


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

@dataclass
class CheckStep:
    """A check applied to a trace."""
    check: Check
    turn_index: int  # Which interaction this check applies to


@dataclass
class InteractionStep:
    """An interaction to execute."""
    inputs: Any
    outputs_fn: Callable[[Any], Any] | None = None  # None = deferred (Suite.run provides target)


class Scenario:
    """A named evaluation scenario with interactions and checks.

    Usage:
        scenario = (
            Scenario("my_test")
            .interact(inputs="hello", outputs_fn=lambda x: my_agent(x))
            .check(FnCheck(fn=lambda t: "hi" in t.last.outputs, name="greets"))
        )
    """
    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description
        self._steps: list[InteractionStep | CheckStep] = []
        self._current_turn = 0

    def interact(
        self,
        inputs: Any,
        outputs_fn: Callable[[Any], Any] | None = None,
    ) -> Scenario:
        """Add an interaction step. If outputs_fn is None, the Suite's target is used."""
        self._steps.append(InteractionStep(inputs=inputs, outputs_fn=outputs_fn))
        self._current_turn += 1
        return self

    def check(self, check: Check) -> Scenario:
        """Add a check against the most recent interaction."""
        # The check applies to the last interaction that was added
        turn = max(0, self._current_turn - 1)
        self._steps.append(CheckStep(check=check, turn_index=turn))
        return self

    async def run(
        self,
        target: Callable[[Any], Any] | None = None,
    ) -> ScenarioResult:
        """Execute the scenario and return results."""
        trace = Trace()
        check_results: list[CheckResult] = []
        t0 = time.monotonic()

        for step in self._steps:
            if isinstance(step, InteractionStep):
                # Execute the interaction
                outputs_fn = step.outputs_fn or target
                if outputs_fn is None:
                    check_results.append(CheckResult(
                        name="setup",
                        status=CheckStatus.ERROR,
                        message="No outputs_fn or target provided for interaction",
                    ))
                    break
                try:
                    outputs = outputs_fn(step.inputs)
                    trace.add(step.inputs, outputs)
                except Exception as e:
                    check_results.append(CheckResult(
                        name=f"interaction_{len(trace.interactions)}",
                        status=CheckStatus.ERROR,
                        message=f"Interaction raised {type(e).__name__}: {e}",
                    ))
                    break

            elif isinstance(step, CheckStep):
                if step.turn_index < len(trace.interactions):
                    result = step.check.evaluate(trace)
                    check_results.append(result)
                else:
                    check_results.append(CheckResult(
                        name=step.check.name,
                        status=CheckStatus.ERROR,
                        message=f"Check references turn {step.turn_index} but only {len(trace.interactions)} interactions exist",
                    ))

        duration = (time.monotonic() - t0) * 1000
        passed = all(r.passed for r in check_results)
        return ScenarioResult(
            name=self.name,
            description=self.description,
            passed=passed,
            check_results=check_results,
            trace=trace,
            duration_ms=duration,
        )


# ---------------------------------------------------------------------------
# Scenario result
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    """Result of running a scenario."""
    name: str
    description: str = ""
    passed: bool = False
    check_results: list[CheckResult] = field(default_factory=list)
    trace: Trace = field(default_factory=Trace)
    duration_ms: float = 0.0

    def print_report(self) -> None:
        """Print a human-readable report."""
        status = "PASSED" if self.passed else "FAILED"
        print(f"\n{'─' * 50} {status} {'─' * 50}")
        for cr in self.check_results:
            icon = "✓" if cr.passed else ("✗" if cr.status == CheckStatus.FAILED else "⚠")
            print(f"  {icon} {cr.name}: {cr.message}")
        print(f"{'─' * 103}")
        print(f"  Trace: {len(self.trace.interactions)} interaction(s), {self.duration_ms:.0f}ms")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "passed": self.passed,
            "checks": [cr.to_dict() for cr in self.check_results],
            "duration_ms": round(self.duration_ms, 1),
        }


# ---------------------------------------------------------------------------
# Suite
# ---------------------------------------------------------------------------

class Suite:
    """Compose multiple scenarios and run them together."""
    def __init__(self, name: str) -> None:
        self.name = name
        self._scenarios: list[Scenario] = []

    def add(self, scenario: Scenario) -> Suite:
        """Add a scenario to the suite."""
        self._scenarios.append(scenario)
        return self

    async def run(
        self,
        target: Callable[[Any], Any] | None = None,
    ) -> SuiteResult:
        """Run all scenarios and return aggregated results."""
        results = []
        t0 = time.monotonic()
        for scenario in self._scenarios:
            result = await scenario.run(target=target)
            results.append(result)
        duration = (time.monotonic() - t0) * 1000
        return SuiteResult(
            name=self.name,
            scenario_results=results,
            duration_ms=duration,
        )


@dataclass
class SuiteResult:
    """Result of running a suite of scenarios."""
    name: str
    scenario_results: list[ScenarioResult] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return all(sr.passed for sr in self.scenario_results)

    @property
    def pass_rate(self) -> float:
        if not self.scenario_results:
            return 0.0
        return sum(1 for sr in self.scenario_results if sr.passed) / len(self.scenario_results)

    def print_report(self) -> None:
        """Print a human-readable suite report."""
        total = len(self.scenario_results)
        passed = sum(1 for sr in self.scenario_results if sr.passed)
        print(f"\n{'=' * 70}")
        print(f"Suite: {self.name}")
        print(f"Results: {passed}/{total} passed ({self.pass_rate * 100:.0f}%)")
        print(f"{'=' * 70}")
        for sr in self.scenario_results:
            icon = "✓" if sr.passed else "✗"
            print(f"  {icon} {sr.name}")
            if not sr.passed:
                for cr in sr.check_results:
                    if not cr.passed:
                        print(f"      ↳ {cr.message}")
        print(f"\n  Total duration: {self.duration_ms:.0f}ms")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "pass_rate": self.pass_rate,
            "scenarios": [sr.to_dict() for sr in self.scenario_results],
            "duration_ms": round(self.duration_ms, 1),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
