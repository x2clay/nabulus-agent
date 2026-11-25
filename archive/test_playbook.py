"""Skill files load in order, and one model call cannot name a scanner.

Called by compile-check.ps1. test_battery.py covers the shape catalog, not this.
"""
import json

import battery
import playbook


def test_one_playbook_follows_the_stack():
    assert playbook.fingerprint(["https://app.example/_next/static/chunks/a.js"]) == "next"
    assert playbook.chosen("next") == "nextjs"
    assert playbook.fingerprint(["https://app.example/wp-content/themes/a.js"]) == "wordpress"
    assert playbook.chosen("wordpress") == "generic"
    assert playbook.fingerprint(["https://app.example/static/app.js"], "csrfmiddlewaretoken") == "django"
    assert playbook.chosen("django") == "generic"
    assert playbook.chosen("generic") == "generic"
    assert playbook.text_for("nextjs").startswith("---")
    assert "framework" in playbook.text_for("generic").lower()
    assert playbook.text_for("not-a-skill") == ""


def test_ask_sends_one_skill_and_keeps_one_request():
    seen = {}

    def call(messages):
        seen["messages"] = messages
        return json.dumps({"requests": [
            {"method": "POST", "url": "https://app.example/api/y", "headers": {"Cookie": "a=1", "Next-Action": "x"}, "body": {"id": "1"}},
            {"method": "GET", "url": "https://evil.example/api"},
            {"tool": "katana", "args": ["-u", "https://app.example"]},
        ]})

    raw = playbook.ask("nextjs", "playbook body", json.dumps({"host": "app.example"}), call)
    system = seen["messages"][0]["content"]
    assert "playbook body" in system
    assert "katana" not in system.lower()
    assert "Do not invent an account" in system
    done = set()
    kept = battery.accept_ideas("app.example", raw, done, limit=8)
    assert len(kept) == 1
    assert kept[0]["method"] == "POST"
    assert kept[0]["data"] == b'{"id": "1"}'
    assert "Cookie" not in kept[0]["headers"]
    assert kept[0]["headers"]["Next-Action"] == "x"


def test_ask_error_is_empty():
    def call(_messages):
        raise TimeoutError("slow")

    assert playbook.ask("idor", "skill", "{}", call) == ""


def test_second_skill_does_not_repeat():
    done = set()
    first = json.dumps({"requests": [{"method": "GET", "url": "https://app.example/api/z", "headers": {"Accept": "application/json"}}]})
    assert len(battery.accept_ideas("app.example", first, done)) == 1
    assert battery.accept_ideas("app.example", first, done) == []


if __name__ == "__main__":
    test_one_playbook_follows_the_stack()
    test_ask_sends_one_skill_and_keeps_one_request()
    test_ask_error_is_empty()
    test_second_skill_does_not_repeat()
    print("playbook ok")
