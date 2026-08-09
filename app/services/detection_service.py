from app.detection.engine import analyze_request


def analyze_detection_request(
    url: str,
    body: str = "",
    headers: dict[str, str] | None = None,
) -> dict:
    """
    Analyze an incoming HTTP-style request.

    The detection engine currently accepts a single string,
    so the URL, body, and headers are combined into one
    searchable request representation.
    """

    headers = headers or {}

    parts = [
        f"URL: {url}",
        f"BODY: {body}",
    ]

    if headers:
        parts.append(
            "HEADERS: "
            + " ".join(
                f"{key}: {value}"
                for key, value in headers.items()
            )
        )

    request_text = "\n".join(parts)

    return analyze_request(request_text)