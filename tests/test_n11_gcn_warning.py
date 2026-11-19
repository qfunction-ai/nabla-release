"""N11 (round 4): --gcn-lof is disabled by default, and enabling it says
why — loudly. An operator flipping an experimental flag must see the
benign-rate ceiling before trusting the output."""


def test_warning_names_the_ceiling(capsys):
    from nabla.pipeline.orchestration import _gcn_lof_warning
    _gcn_lof_warning()
    err = capsys.readouterr().err
    assert "GCN-LOF is EXPERIMENTAL" in err
    assert "13-18%" in err and "BENIGN" in err
    assert "deferred" in err


def test_gcn_disabled_by_default_everywhere():
    """The knob defaults off at every entry point (R3/N11)."""
    import inspect
    from nabla.pipeline import detection, orchestration
    for fn in (detection.run_detection, orchestration.run_pipeline):
        sig = inspect.signature(fn)
        assert sig.parameters["gcn_lof_enabled"].default is False, (
            f"{fn.__name__} must default gcn_lof_enabled to False"
        )
