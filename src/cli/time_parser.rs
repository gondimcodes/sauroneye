use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};

pub fn parse_time_argument(arg: &str) -> Result<i64, String> {
    let trimmed = arg.trim();
    if trimmed.eq_ignore_ascii_case("now") {
        return Ok(Utc::now().timestamp());
    }

    // Try full datetime "YYYY-MM-DD HH:MM:SS"
    if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&ndt).timestamp());
    }

    // Try datetime with minute precision "YYYY-MM-DD HH:MM"
    if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M") {
        return Ok(Utc.from_utc_datetime(&ndt).timestamp());
    }

    // Try date only "YYYY-MM-DD" -> Start of Day 00:00:00 UTC
    if let Ok(nd) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        if let Some(ndt) = nd.and_hms_opt(0, 0, 0) {
            return Ok(Utc.from_utc_datetime(&ndt).timestamp());
        }
    }

    // Try ISO 8601 / RFC 3339
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.timestamp());
    }

    Err(format!(
        "Invalid date/time format: '{}'. Expected 'YYYY-MM-DD HH:MM:SS', 'YYYY-MM-DD' or 'now'",
        arg
    ))
}
