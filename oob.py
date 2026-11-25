#!/usr/bin/env python3
"""oob.py - pluggable out-of-band (OOB) validators for the vector probes.

A finding is only real when a DETERMINISTIC validator proves it (XBOW doctrine). The validator
is an OOB interaction: we inject a URL carrying a unique per-injection MARKER; if the target
server contacts our listener for that marker, the server made an outbound request for us = proof.

Two providers, same interface:
  * LocalOOB      - our own 127.0.0.1 listener (oob_server.py). Lab only; nablus-local.
  * InteractshOOB - public/self-hosted interactsh (DNS + HTTP). Works against REAL internet
                    targets because the TARGET calls the public OOB server, not us.

Interface:
  provider.start()                 -> ready (InteractshOOB spins up the client, learns its domain)
  provider.payload(marker)         -> a URL to inject that is attributable to `marker`
  provider.seen_markers()          -> set() of markers that produced an interaction
  provider.stop()                  -> teardown

Correlation rule (both providers): ONLY markers we generated count. interactsh self-check hits
(full-id == unique-id, no marker label) are ignored so they can never cause a false positive.
"""
from __future__ import annotations
import subprocess, re, json, time, pathlib


class LocalOOB:
    """Local listener: oob_server.py logs each inbound request path to a JSONL file.
    Marker is carried in the URL path, e.g. http://127.0.0.1:9099/<marker>."""
    def __init__(self, base_url: str, logpath: str, settle: float = 0.6):
        self.base = base_url.rstrip("/")
        self.log = pathlib.Path(logpath)
        self.settle = settle

    def start(self):
        return self

    def payload(self, marker: str, path: str | None = None) -> str:
        return f"{self.base}/{marker}"

    def wait(self):
        time.sleep(self.settle)

    def seen_markers(self) -> set:
        out = set()
        if not self.log.exists():
            return out
        for ln in self.log.read_text(errors="replace").splitlines():
            try:
                rec = json.loads(ln)
            except Exception:
                continue
            path = (rec.get("path") or "").strip("/")
            if path:
                out.add(path.split("/")[0])
        return out

    def stop(self):
        pass


class InteractshOOB:
    """interactsh client session. Marker is carried as the leftmost DNS label:
    http://<marker>.<session-domain>/<marker>. Confirmed via full-id == '<marker>.<session-id>'."""
    _DOMAIN_RE = re.compile(r"([a-z0-9]+\.oast\.[a-z]+)")

    def __init__(self, client_path: str, workdir: str, server: str | None = None,
                 poll_wait: float = 11.0, start_timeout: float = 35.0):
        self.client = client_path
        self.wd = pathlib.Path(workdir)
        self.server = server
        self.poll_wait = poll_wait
        self.start_timeout = start_timeout
        self.jsonl = self.wd / "itsh_live.jsonl"
        self.errf = self.wd / "itsh_live.err"
        self.proc = None
        self.domain = None

    def start(self):
        for f in (self.jsonl, self.errf):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        args = [self.client, "-json", "-o", str(self.jsonl)]
        if self.server:
            args += ["-server", self.server]
        self._ef = open(self.errf, "w")
        self.proc = subprocess.Popen(args, stdout=self._ef, stderr=self._ef)
        deadline = time.time() + self.start_timeout
        while time.time() < deadline:
            if self.errf.exists():
                m = self._DOMAIN_RE.search(self.errf.read_text(errors="replace"))
                if m:
                    self.domain = m.group(1)
                    return self
            if self.proc.poll() is not None:
                raise RuntimeError("interactsh-client exited before registering (see itsh_live.err)")
            time.sleep(1)
        self.stop()
        raise RuntimeError("interactsh: no payload domain within start_timeout")

    def payload(self, marker: str, path: str | None = None) -> str:
        p = path if path is not None else f"/{marker}"
        return f"http://{marker}.{self.domain}{p}"

    def wait(self):
        time.sleep(self.poll_wait)

    def seen_markers(self) -> set:
        out = set()
        if not self.jsonl.exists():
            return out
        for ln in self.jsonl.read_text(errors="replace").splitlines():
            try:
                rec = json.loads(ln)
            except Exception:
                continue
            fid = rec.get("full-id", "")
            if "." in fid:                      # has a marker label; base self-checks have none
                out.add(fid.split(".")[0])
        return out

    def interactions_for(self, marker: str) -> list:
        """Full interaction records for a marker (for evidence in findings)."""
        hits = []
        if not self.jsonl.exists():
            return hits
        for ln in self.jsonl.read_text(errors="replace").splitlines():
            try:
                rec = json.loads(ln)
            except Exception:
                continue
            if rec.get("full-id", "").split(".")[0] == marker and "." in rec.get("full-id", ""):
                hits.append({k: rec.get(k) for k in ("protocol", "full-id", "q-type",
                                                     "remote-address", "timestamp")})
        return hits

    def stop(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(5)
                except Exception:
                    self.proc.kill()
        finally:
            try:
                self._ef.close()
            except Exception:
                pass
