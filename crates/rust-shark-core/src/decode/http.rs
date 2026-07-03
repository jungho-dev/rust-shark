use super::HttpInfo;

/// Decode an HTTP/1.x request or response head from the start of a (possibly
/// reassembled) byte stream. Only the header block is parsed; the body may be
/// binary and is ignored. Returns `None` if the start does not look like HTTP/1.x.
pub fn try_decode_http(stream: &[u8]) -> Option<HttpInfo> {
    let sep = find_subslice(stream, b"\r\n\r\n");
    let head_end = sep.map(|i| i + 2).unwrap_or_else(|| stream.len().min(8192));
    // Body begins after the full CRLFCRLF separator (when present in-segment).
    let body_start = sep.map(|i| i + 4).unwrap_or(stream.len());
    let head = &stream[..head_end];
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    if first.is_empty() {
        return None;
    }

    let mut info = HttpInfo {
        is_request: false,
        method: None,
        uri: None,
        version: None,
        status_code: None,
        headers: Vec::new(),
        host: None,
        content_length: None,
        chunked: false,
        query_params: Vec::new(),
        body_params: Vec::new(),
        header_range: (0, head_end),
    };

    if let Some(rest) = first.strip_prefix("HTTP/") {
        // Status line: "HTTP/x.y CODE reason"
        let mut p = rest.splitn(2, ' ');
        info.version = Some(format!("HTTP/{}", p.next()?));
        info.status_code = p.next().and_then(|s| s.split(' ').next()?.parse().ok());
        info.status_code?; // must have a numeric code
    } else {
        // Request line: "METHOD URI HTTP/x.y"
        let mut p = first.splitn(3, ' ');
        let method = p.next()?;
        if !is_http_method(method) {
            return None;
        }
        let uri = p.next()?;
        let version = p.next()?;
        if !version.starts_with("HTTP/") {
            return None;
        }
        info.is_request = true;
        info.method = Some(method.to_string());
        info.uri = Some(uri.to_string());
        info.version = Some(version.to_string());
    }

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            match k.to_ascii_lowercase().as_str() {
                "host" => info.host = Some(v.to_string()),
                "content-length" => info.content_length = v.parse().ok(),
                "transfer-encoding" if v.eq_ignore_ascii_case("chunked") => info.chunked = true,
                _ => {}
            }
            info.headers.push((k.to_string(), v.to_string()));
        }
    }

    // Request parameters for display: URI query string plus a form-urlencoded
    // or JSON request body, when the body is present in this captured segment.
    if let Some(uri) = &info.uri {
        if let Some((_, query)) = uri.split_once('?') {
            info.query_params = parse_form_params(query);
        }
    }
    let body = stream.get(body_start..).unwrap_or(&[]);
    if !body.is_empty() {
        let ctype = info
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_ascii_lowercase())
            .unwrap_or_default();
        if ctype.contains("application/json") || (ctype.is_empty() && looks_like_json(body)) {
            info.body_params = parse_json_params(body);
        } else if ctype.contains("x-www-form-urlencoded") {
            if let Ok(s) = std::str::from_utf8(body) {
                info.body_params = parse_form_params(s);
            }
        }
    }

    Some(info)
}

// 1. body/query parameter parsing ---------------------------------------------

/// Split `a=1&b=2` form data into percent-decoded key/value pairs.
fn parse_form_params(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (url_decode(k), url_decode(v)),
            None => (url_decode(pair), String::new()),
        })
        .collect()
}

/// Flatten a top-level JSON object into key/value strings (nested values render
/// as compact JSON). A non-object or unparsable body yields no parameters.
fn parse_json_params(body: &[u8]) -> Vec<(String, String)> {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(map)) => map
            .into_iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => (k, s),
                other => (k, other.to_string()),
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// First non-whitespace byte is `{` or `[` — a cheap JSON-body sniff.
fn looks_like_json(body: &[u8]) -> bool {
    matches!(
        body.iter().copied().find(|b| !b.is_ascii_whitespace()),
        Some(b'{') | Some(b'[')
    )
}

/// Percent-decode a form field, treating `+` as space and leaving invalid
/// escapes literal. Decoded bytes are interpreted as UTF-8 (lossy).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_http_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "TRACE" | "CONNECT"
    )
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request() {
        let info = try_decode_http(
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert!(info.is_request);
        assert_eq!(info.method.as_deref(), Some("GET"));
        assert_eq!(info.uri.as_deref(), Some("/index.html"));
        assert_eq!(info.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_response_chunked() {
        let info = try_decode_http(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert!(!info.is_request);
        assert_eq!(info.status_code, Some(200));
        assert!(info.chunked);
    }

    #[test]
    fn test_query_and_form_params() {
        let info = try_decode_http(
            b"POST /p?page=0&log=ins HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nACTION=go&PAGE_ID=110203",
        )
        .unwrap();
        assert_eq!(
            info.query_params,
            vec![
                ("page".to_string(), "0".to_string()),
                ("log".to_string(), "ins".to_string())
            ]
        );
        assert_eq!(
            info.body_params,
            vec![
                ("ACTION".to_string(), "go".to_string()),
                ("PAGE_ID".to_string(), "110203".to_string())
            ]
        );
    }

    #[test]
    fn test_json_body_params() {
        let mut req =
            b"POST /l HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n".to_vec();
        req.extend_from_slice(br#"{"oper":"cpidListSearch","iRows":30,"log":"ins"}"#);
        let info = try_decode_http(&req).unwrap();
        assert!(
            info.body_params
                .contains(&("oper".to_string(), "cpidListSearch".to_string()))
        );
        assert!(
            info.body_params
                .contains(&("iRows".to_string(), "30".to_string()))
        );
    }

    #[test]
    fn test_url_decode_percent_and_plus() {
        let info = try_decode_http(
            b"POST /p HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=%41%42+C",
        )
        .unwrap();
        assert_eq!(
            info.body_params,
            vec![("q".to_string(), "AB C".to_string())]
        );
    }

    #[test]
    fn test_not_http() {
        assert!(try_decode_http(b"\x16\x03\x01\x00\x05hello").is_none());
        assert!(try_decode_http(b"random text\r\n\r\n").is_none());
    }
}
