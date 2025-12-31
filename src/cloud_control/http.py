import requests
from requests.exceptions import HTTPError


def raise_http_error(r: requests.Response) -> None:
    if r.ok:
        return

    try:
        errors = r.json()["errors"]
    except:  # noqa:E722
        r.raise_for_status()

    url = r.request.url

    msg = [f"{r.status_code} {r.reason} for url: {url}"] + errors
    msg = "; ".join(msg)
    raise HTTPError(msg)
