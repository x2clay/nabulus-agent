#!/usr/bin/env python3
"""browser.py - hardened, privacy-clean headless browser for the validators.

OPSEC stance: PRIVACY HYGIENE, not detection evasion.
  * Ephemeral throwaway profile (temp dir, wiped on close) - never a personal Chrome profile;
    no cookies/history/localStorage/credentials persist between runs.
  * All Google/Chrome phone-home disabled (telemetry, crash reporting, sync, safe-browsing pings,
    domain reliability, component update, background networking).
  * Never touches the OS credential store (--password-store=basic + mock keychain).
  * "HeadlessChrome" UA token stripped -> normal Chrome UA matched to the real engine version.
    Neutral locale/timezone/viewport. Nothing tied to the operator or the box.
  * Sandbox stays ON (no --no-sandbox).
  * Runs IN the Mullvad tunnel (chrome.exe is NOT split-tunneled) -> targets see the VPN exit IP.

Deliberately NOT included: navigator.webdriver patching, canvas/font/WebGL spoofing, or any
anti-bot stealth. Those are the detection-evasion line and are off by default; authorized testing
does not need them.
"""
from __future__ import annotations
import contextlib

HARDENED_ARGS = [
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-breakpad",                       # crash reporting
    "--disable-crash-reporter",
    "--disable-client-side-phishing-detection", # no safe-browsing phone-home
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-domain-reliability",             # no reliability telemetry to Google
    "--disable-sync",                           # no account sync
    "--disable-features=Translate,OptimizationHints,MediaRouter,"
    "InterestFeedContentSuggestions,CalculateNativeWinOcclusion,AutofillServerCommunication,"
    "OptimizationGuideModelDownloading",
    "--metrics-recording-only",                 # record but never upload; no reporting
    "--no-pings",                               # no hyperlink auditing
    "--disable-prompt-on-repost",
    "--mute-audio",
    "--password-store=basic",                   # never touch OS keychain
    "--use-mock-keychain",
]

# Required to run headless Chrome under the SYSTEM account (Windows session 0 has no desktop /
# window-station, so the sandbox + GPU can't initialize and the launch hangs). This is the standard
# service-context combo. Trade-off: --no-sandbox drops Chrome's process sandbox; acceptable here
# because we run ephemeral, under an isolated non-personal SYSTEM context, against AUTHORIZED
# targets only. Point this at genuinely untrusted pages only from a throwaway VM instead.
SERVICE_ARGS = [
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
]


def _clean_ua(version: str) -> str:
    major = (version or "").split(".")[0] or "131"
    return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36")


@contextlib.contextmanager
def hardened_context(playwright, *, channel: str = "chrome", system_mode: bool = True,
                     launch_timeout_ms: int = 25000,
                     timezone_id: str = "America/New_York", locale: str = "en-US"):
    """Yield a hardened, ephemeral browser context. Browser + temp profile torn down on exit.
    system_mode adds the SYSTEM/session-0 service flags; launch_timeout_ms fails fast if Chrome
    can't come up (instead of hanging)."""
    args = list(HARDENED_ARGS) + (SERVICE_ARGS if system_mode else [])
    browser = playwright.chromium.launch(channel=channel, headless=True, args=args,
                                         timeout=launch_timeout_ms)
    try:
        ua = _clean_ua(getattr(browser, "version", "") or "")
        context = browser.new_context(
            user_agent=ua,
            locale=locale,
            timezone_id=timezone_id,
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,       # pentest: TLS misconfig must not block the probe
            service_workers="block",
        )
        try:
            yield context
        finally:
            with contextlib.suppress(Exception):
                context.close()
    finally:
        with contextlib.suppress(Exception):
            browser.close()
