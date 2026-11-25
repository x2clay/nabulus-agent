"""Does AUTHENTICATED capture reach object refs that unauth capture cannot?
Blind-safe: prints counts only (pages / calls / ownable refs), never URLs."""
import os, session, idor
host = "127.0.0.1:8099"
state = str(session.SESSIONS / f"{host}.storage.json")
acct = {"host": host, "username": "alice", "password": "Sunflower#A1pha",
        "login_url": "http://127.0.0.1:8099/",
        "username_selector": "input[name='username']",
        "password_selector": "input[name='password']",
        "submit_selector": "button[type='submit'], input[type='submit'], button",
        "success_url_contains": ""}
r = session.login_one(acct, headed=False, max_pages=6)
print("login_one ok:", r.get("ok"), "| state file:", os.path.exists(state))

def refs(calls):
    return len(idor.harvest_object_refs(calls, []))

un = session.open_host(host); un_calls = session.calls_for(host)
print("UNAUTH  found:", un.get("found"), "| calls:", len(un_calls), "| object-refs:", refs(un_calls))
au = session.open_host(host, state_path=state); au_calls = session.calls_for(host)
print("AUTHED  found:", au.get("found"), "| calls:", len(au_calls), "| object-refs:", refs(au_calls))
