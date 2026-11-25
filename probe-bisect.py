"""Find which Chrome launch flag closes the connection. Status only."""
from playwright.sync_api import sync_playwright

BASE = [
    "--disable-blink-features=AutomationControlled",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-sync",
    "--no-first-run",
    "--disable-background-networking",
    "--lang=en-US",
]
URL = "https://www.quantnq.com/"


def once(label: str, args: list[str]) -> None:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                channel="chrome",
                args=args,
                ignore_default_args=["--enable-automation"],
            )
            page = browser.new_page()
            resp = page.goto(URL, wait_until="commit", timeout=25000)
            status = resp.status if resp else 0
            print(f"{label} status={status}", flush=True)
            browser.close()
    except Exception as exc:
        print(f"{label} ERR {str(exc).splitlines()[0][:160]}", flush=True)


if __name__ == "__main__":
    once("all", BASE)
    once("no-webrtc", [a for a in BASE if "webrtc" not in a])
    once("no-bg", [a for a in BASE if a != "--disable-background-networking"])
    once("blink-only", ["--disable-blink-features=AutomationControlled"])
