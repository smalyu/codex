use codex_backend_openapi_models::models::RateLimitStatusPayload as BackendRateLimitStatusPayload;
use codex_backend_openapi_models::models::RateLimitWindowSnapshot as BackendRateLimitWindowSnapshot;
use codex_protocol::protocol::RateLimitSnapshot;
use codex_protocol::protocol::RateLimitWindow;

pub fn rate_limit_snapshot_from_usage_payload(
    payload: BackendRateLimitStatusPayload,
) -> RateLimitSnapshot {
    let Some(details) = payload
        .rate_limit
        .and_then(|inner| inner.map(|boxed| *boxed))
    else {
        return RateLimitSnapshot {
            primary: None,
            secondary: None,
        };
    };

    RateLimitSnapshot {
        primary: map_rate_limit_window(details.primary_window),
        secondary: map_rate_limit_window(details.secondary_window),
    }
}

fn map_rate_limit_window(
    window: Option<Option<Box<BackendRateLimitWindowSnapshot>>>,
) -> Option<RateLimitWindow> {
    let snapshot = match window {
        Some(Some(snapshot)) => *snapshot,
        _ => return None,
    };

    let used_percent = f64::from(snapshot.used_percent);
    let window_minutes = window_minutes_from_seconds(snapshot.limit_window_seconds);
    let resets_at = Some(i64::from(snapshot.reset_at));

    Some(RateLimitWindow {
        used_percent,
        window_minutes,
        resets_at,
    })
}

fn window_minutes_from_seconds(seconds: i32) -> Option<i64> {
    if seconds <= 0 {
        return None;
    }

    let seconds_i64 = i64::from(seconds);
    Some((seconds_i64 + 59) / 60)
}
