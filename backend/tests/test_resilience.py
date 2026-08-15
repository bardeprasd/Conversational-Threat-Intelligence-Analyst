from app.rate_limit import SlidingWindowRateLimiter
from app.services import ThreatIntelService, ThreatToolbox


class FailingLiveClient:
    def lookup_ioc(self, **_kwargs):
        raise TimeoutError("provider timed out")


def test_provider_exception_becomes_grounded_error_not_hallucination():
    toolbox = ThreatToolbox(ThreatIntelService(live_client=FailingLiveClient()))
    result = toolbox.execute(
        "lookup_ioc", trace_id="tr_failure", indicator="45.83.122.10"
    )
    assert result.status == "error"
    assert result.finding == {}
    assert result.evidence == []
    assert "unavailable" in result.warnings[0]


def test_sliding_window_rate_limit_and_recovery():
    now = [100.0]
    limiter = SlidingWindowRateLimiter(2, 10, clock=lambda: now[0])
    assert limiter.allow("analyst")[0]
    assert limiter.allow("analyst")[0]
    allowed, retry_after = limiter.allow("analyst")
    assert not allowed
    assert retry_after > 0
    now[0] = 111.0
    assert limiter.allow("analyst")[0]
