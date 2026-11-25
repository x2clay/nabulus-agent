"""One Chrome navigation check. Prints status codes only."""
from playwright.sync_api import sync_playwright

URLS = (
    "https://example.com/",
    "https://www.quantnq.com/",
    "https://quantnq.com/",
)


def run(label: str, args: list[str]) -> None:
    print("MODE", label, flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            channel="chrome",
            args=args,
            ignore_default_args=["--enable-automation"],
        )
        page = browser.new_page()
        for url in URLS:
            try:
                resp = page.goto(url, wait_until="commit", timeout=25000)
                status = resp.status if resp else 0
                final = page.url.split("?", 1)[0][:160]
                print(f"{url} status={status} final={final}", flush=True)
            except Exception as exc:
                line = str(exc).splitlines()[0][:180]
                print(f"{url} ERR {line}", flush=True)
        browser.close()


if __name__ == "__main__":
    run("stock", [])
    run("noquic", ["--disable-quic"])
