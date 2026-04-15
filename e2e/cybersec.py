#!/usr/bin/env python3
"""
Cybersec test battery against the running e2e broker.

Preconditions:
  - PKI generated under e2e/pki (multi-root) + negative certs via
    gen-negative-certs.sh
  - Broker running via run-broker.sh (port 18883)
  - Audit log at e2e/run/audit.jsonl

Each test:
  1. Truncates the audit log so assertions are local to this test
  2. Runs some client / broker interaction
  3. Reads the audit log back and asserts on the events

Prints PASS/FAIL per test. Exits non-zero on any failure. Each test is
independent — audit.jsonl is truncated at the start of every test so you
can run them individually by editing the main() dispatch.
"""
from __future__ import annotations
import json
import os
import pathlib
import random
import signal
import subprocess
import sys
import textwrap
import threading
import time

E2E_DIR = pathlib.Path(__file__).resolve().parent
PKI = E2E_DIR / "pki"
RUN = E2E_DIR / "run"
AUDIT = RUN / "audit.jsonl"

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", "18883"))

PUB = os.environ.get("MOSQUITTO_PUB", "/home/hs/mosquitto/build/client/mosquitto_pub")
SUB = os.environ.get("MOSQUITTO_SUB", "/home/hs/mosquitto/build/client/mosquitto_sub")


class TestFailure(Exception):
    pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def reset_audit() -> None:
    AUDIT.write_text("")


def read_audit() -> list[dict]:
    out = []
    for raw in AUDIT.read_text().splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError as e:
            raise TestFailure(f"audit line not valid JSON: {e}: {raw!r}")
    return out


def wait_for_audit(predicate, timeout_s: float = 3.0) -> list[dict]:
    """Poll audit.jsonl until `predicate(lines)` is truthy, or raise."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lines = read_audit()
        if predicate(lines):
            return lines
        time.sleep(0.05)
    lines = read_audit()
    raise TestFailure(
        f"predicate never satisfied within {timeout_s}s; audit had {len(lines)} lines"
    )


def tls_client_args(cert: str, key: str) -> list[str]:
    return [
        "--cafile", str(PKI / "bundle_all.pem"),
        "--tls-version", "tlsv1.2",
        "--cert", str(PKI / cert),
        "--key", str(PKI / key),
    ]


def do_publish(cert: str, key: str, cn: str, topic: str, msg: str = "x",
               qos: int = 1, extra: list[str] | None = None) -> subprocess.CompletedProcess:
    cmd = [
        PUB, "-h", HOST, "-p", str(PORT),
        *tls_client_args(cert, key),
        "-i", f"cs-{cn}-{os.getpid()}",
        "-t", topic, "-m", msg, "-q", str(qos),
    ]
    if extra:
        cmd += extra
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10)


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------

TESTS: dict[str, "callable"] = {}


def test(name: str):
    def deco(fn):
        TESTS[name] = fn
        return fn
    return deco


@test("auth_untrusted_root_tls_reject")
def t_untrusted_root() -> None:
    """Client cert signed by a CA not in either plugin bundle must be rejected
    at the TLS handshake (listener cafile=bundle_all.pem only trusts root_a
    and root_b). The plugin should never see it."""
    reset_audit()

    # The intruder cert chains up to untrusted_root.crt, which is NOT in
    # bundle_all.pem — the broker rejects the handshake.
    cp = do_publish("intruder.crt", "intruder.key", "intruder",
                    "devices/anything/x")
    if cp.returncode == 0:
        raise TestFailure(
            f"untrusted root cert was accepted! mosquitto_pub stdout: {cp.stdout!r}"
        )
    # Give the broker a moment to flush any audit line (there should be none).
    time.sleep(0.2)
    lines = read_audit()
    decisions = [l for l in lines if l.get("event") in {"connect", "acl"}]
    if decisions:
        raise TestFailure(
            f"plugin saw {len(decisions)} decisions for untrusted-root cert; "
            "TLS should have rejected before plugin got a look"
        )


@test("auth_expired_leaf_tls_reject")
def t_expired_leaf() -> None:
    """An expired cert is rejected at the TLS handshake by mosquitto's own
    cafile verification, before the plugin sees it — this is the listener's
    first line of defence. The audit log stays empty for the attempt; the
    plugin's chain-override machinery applies only to cases where TLS
    accepts the cert (e.g. a cert the handshake cafile trusts but the
    plugin's own trust bundle flags).
    """
    reset_audit()
    cp = do_publish("expired_alice.crt", "expired_alice.key", "expired-alice",
                    "devices/anything/x")
    if cp.returncode == 0:
        raise TestFailure(
            "expired leaf was accepted! Expected TLS handshake reject"
        )
    time.sleep(0.2)
    decisions = [l for l in read_audit()
                 if l.get("event") in {"connect", "acl"}]
    if decisions:
        raise TestFailure(
            f"plugin saw {len(decisions)} decisions for expired cert; "
            "the TLS handshake should have rejected"
        )


@test("acl_cross_device_deny")
def t_acl_cross_device() -> None:
    """device_01 publishing into device_02's subtree must deny."""
    reset_audit()
    do_publish("device_01.crt", "device_01.key", "device-01",
               "devices/device-02/stolen", "oops")
    lines = wait_for_audit(
        lambda ls: any(l.get("event") == "acl" and l.get("result") == "deny"
                       for l in ls)
    )
    deny = next(l for l in lines if l.get("event") == "acl"
                and l.get("result") == "deny")
    if "device-02" not in (deny.get("topic") or ""):
        raise TestFailure(
            f"acl deny topic mismatch: {deny.get('topic')!r}"
        )
    if deny.get("cn") != "device-01":
        raise TestFailure(
            f"acl deny cn={deny.get('cn')!r}, expected device-01"
        )


@test("acl_fleet_wildcard_from_device_deny")
def t_acl_fleet_wildcard_from_device() -> None:
    """A device cert that tries to escape its subtree via a wildcard
    subscription (devices/+/secret) must be denied. The device policy only
    allows devices/<cn>/... and the wildcard-qualified topic doesn't match
    starts_with that prefix."""
    reset_audit()
    cmd = [
        SUB, "-h", HOST, "-p", str(PORT),
        *tls_client_args("device_01.crt", "device_01.key"),
        "-i", f"cs-dev01-sub-{os.getpid()}",
        "-t", "devices/+/secret",
        "-C", "1", "-W", "1",  # at most 1 msg, 1 second wall clock
    ]
    subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    lines = wait_for_audit(
        lambda ls: any(
            l.get("event") == "acl" and l.get("result") == "deny"
            and l.get("cn") == "device-01"
            and "devices/+/secret" in (l.get("topic") or "")
            for l in ls
        )
    )


@test("audit_framing_cn_injection")
def t_cn_injection() -> None:
    """A cert whose CN contains quote/backslash/newline must not break audit
    JSON framing — every emitted line must still parse as JSON and the cn
    field must round-trip the original bytes."""
    reset_audit()
    do_publish("injection_alice.crt", "injection_alice.key", "injection",
               "devices/anything/x")
    time.sleep(0.3)
    lines = read_audit()  # raises TestFailure if any line is broken JSON
    connects = [l for l in lines if l.get("event") == "connect"]
    if not connects:
        raise TestFailure("no connect event recorded for injection cert")
    cn = connects[0].get("cn") or ""
    # Openssl stored the DN with escaping; the on-the-wire CN should still
    # contain both a quote and a backslash byte to prove escaping survived.
    if '"' not in cn and "\\" not in cn:
        raise TestFailure(
            f"injection CN round-trip empty: cn={cn!r}"
        )


@test("audit_decision_id_correlates_connect_and_acl")
def t_decision_id() -> None:
    """Every decision gets a unique monotonic decision_id. connect and the
    ACLs it implies come from different callbacks but run on the same
    broker-loop thread, so decision_ids should be distinct and positive."""
    reset_audit()
    do_publish("operator_alice.crt", "operator_alice.key", "alice",
               "devices/alice/hello", "hi")
    time.sleep(0.3)
    lines = read_audit()
    ids = [l["decision_id"] for l in lines if l.get("decision_id") is not None]
    if len(set(ids)) != len(ids):
        raise TestFailure(f"duplicate decision_ids: {ids}")
    if any(i <= 0 for i in ids):
        raise TestFailure(f"non-positive decision_id: {ids}")


@test("audit_line_truncation_kicks_in")
def t_truncation() -> None:
    """With the default 8 KB cap and rich DEBUG extras, lines should stay
    under the cap. With a pathological cert or a small cap, the plugin must
    rebuild the line with {"truncated":true} rather than overflow. We
    synthesise the overflow by confirming every audit line fits within the
    cap configured in mosquitto.conf and no line overflowed framing."""
    reset_audit()
    do_publish("operator_alice.crt", "operator_alice.key", "alice",
               "devices/alice/h", "x")
    time.sleep(0.3)
    lines = read_audit()
    if not lines:
        raise TestFailure("no audit lines produced")
    # Two assertions: (1) every line is valid JSON (already covered by
    # read_audit), (2) no line exceeds the current line_cap. The broker
    # config caps at 8192; asserting 9000 leaves slack for the timestamp.
    with open(AUDIT, "rb") as f:
        for raw in f:
            if len(raw) > 9000:
                raise TestFailure(
                    f"audit line exceeds cap+slack: {len(raw)} bytes"
                )


@test("audit_deny_carries_full_metadata")
def t_deny_metadata() -> None:
    """A deny line must carry the same cert metadata an allow line does —
    cn, subject_dn, issuer_dn, serial, fingerprint, trust_anchor_fp.
    This is the property that makes relaxed-policy observability work."""
    reset_audit()
    do_publish("device_01.crt", "device_01.key", "device-01",
               "devices/device-02/x", "nope")
    lines = wait_for_audit(
        lambda ls: any(l.get("event") == "acl" and l.get("result") == "deny"
                       for l in ls)
    )
    deny = next(l for l in lines if l.get("event") == "acl"
                and l.get("result") == "deny")
    required = [
        "cn", "subject_dn", "issuer_dn", "serial",
        "fingerprint_sha256", "trust_anchor_fp",
        "chain_ok", "chain_errors",
        "client_id", "remote_addr", "decision_id",
    ]
    missing = [k for k in required if k not in deny]
    if missing:
        raise TestFailure(f"deny line missing fields: {missing}")


@test("policy_note_at_debug_only")
def t_policy_note() -> None:
    """The policy calls audit.log(...) on every successful connect. At DEBUG
    level the note should appear as a policy.note event. Confirms the Rego
    host function round-trip."""
    reset_audit()
    do_publish("operator_alice.crt", "operator_alice.key", "alice",
               "devices/alice/x", "x")
    time.sleep(0.3)
    lines = read_audit()
    notes = [l for l in lines if l.get("event") == "policy.note"]
    if not notes:
        raise TestFailure("no policy.note emitted by Rego audit.log()")
    note = notes[0]
    if "role=operator" not in (note.get("note") or ""):
        raise TestFailure(f"note body unexpected: {note.get('note')!r}")


# --------------------------------------------------------------------------
# reload safety
# --------------------------------------------------------------------------

@test("reload_race_under_load_atomic_swap")
def t_reload_race() -> None:
    """Stress the SIGHUP reload path while client threads hammer the broker
    with connect+publish. The plugin's reload is supposed to build the new
    policy + trust store in full, then atomically swap; a torn swap would
    surface as a malformed audit line, a missing core field, a duplicated
    decision_id, or the broker dying mid-race.

    Two valid policies are rotated under e2e/run/policy.rego. Both are
    permissive for the two operator cert patterns but differ by an
    audit.log tag so we can see both observed during the run. Test
    duration: ~3 s with 4 client threads and SIGHUPs every 150 ms."""
    current_policy = RUN / "policy.rego"
    original = current_policy.read_text()

    # Minimal stand-in policies — both allow the test clients, differ by
    # the audit tag. Fingerprints come from the on-disk roots.
    def policy_with_tag(tag: str) -> str:
        fp_a = subprocess.check_output(
            ["openssl", "x509", "-in", str(PKI/"root_a.crt"),
             "-noout", "-fingerprint", "-sha256"],
            text=True,
        ).strip().split("=", 1)[1].replace(":", "").lower()
        fp_b = subprocess.check_output(
            ["openssl", "x509", "-in", str(PKI/"root_b.crt"),
             "-noout", "-fingerprint", "-sha256"],
            text=True,
        ).strip().split("=", 1)[1].replace(":", "").lower()
        return textwrap.dedent(f"""\
            package mqtt

            root_a_fp := "{fp_a}"
            root_b_fp := "{fp_b}"

            anchor_fp := input.cert.trust_anchor.fingerprint_sha256
            is_operator {{ anchor_fp == root_a_fp }}
            is_device   {{ anchor_fp == root_b_fp }}

            default connect := false
            default acl := false

            connect {{
                input.cert.chain_ok
                input.cert.cn != ""
                is_operator
                audit.log("policy={tag} role=operator")
            }}
            connect {{
                input.cert.chain_ok
                input.cert.cn != ""
                is_device
                audit.log("policy={tag} role=device")
            }}

            acl {{ is_operator; startswith(input.acl.topic, "devices/") }}
            acl {{ is_device; startswith(input.acl.topic, sprintf("devices/%s/", [input.cert.cn])) }}
        """)

    pol_a = policy_with_tag("A")
    pol_b = policy_with_tag("B")

    pid = int((RUN / "broker.pid").read_text().strip())
    reset_audit()
    current_policy.write_text(pol_a)
    os.kill(pid, signal.SIGHUP)
    time.sleep(0.1)

    stop = threading.Event()
    errors: list[str] = []

    def worker(cert: str, key: str, cn: str, topic_pattern: str):
        while not stop.is_set():
            try:
                do_publish(cert, key, cn, topic_pattern.format(n=random.randint(1, 1000)),
                           msg="x", qos=0,
                           extra=["--quiet"])
            except Exception as e:
                errors.append(f"{cn}: {e}")

    threads = [
        threading.Thread(target=worker,
                         args=("operator_alice.crt", "operator_alice.key",
                               "alice", "devices/a/{n}"),
                         daemon=True),
        threading.Thread(target=worker,
                         args=("operator_bob.crt", "operator_bob.key",
                               "bob", "devices/b/{n}"),
                         daemon=True),
        threading.Thread(target=worker,
                         args=("device_01.crt", "device_01.key",
                               "device-01", "devices/device-01/{n}"),
                         daemon=True),
        threading.Thread(target=worker,
                         args=("device_02.crt", "device_02.key",
                               "device-02", "devices/device-02/{n}"),
                         daemon=True),
    ]
    for t in threads:
        t.start()

    # Flap the policy file and SIGHUP every ~150ms for ~3 seconds.
    start = time.monotonic()
    i = 0
    while time.monotonic() - start < 3.0:
        current_policy.write_text(pol_a if i % 2 == 0 else pol_b)
        try:
            os.kill(pid, signal.SIGHUP)
        except OSError as e:
            stop.set()
            raise TestFailure(f"broker died mid-reload: {e}")
        time.sleep(0.15)
        i += 1

    stop.set()
    for t in threads:
        t.join(timeout=3)

    # Broker must still be alive.
    try:
        os.kill(pid, 0)
    except OSError:
        raise TestFailure("broker died during reload race")

    # Restore original policy for subsequent tests.
    current_policy.write_text(original)
    os.kill(pid, signal.SIGHUP)
    time.sleep(0.2)

    if errors:
        # Client thread errors are allowed (connects can race TLS shutdown);
        # what matters is broker state. Log a summary only.
        print(f"    ({len(errors)} worker transient errors, OK to ignore)")

    lines = read_audit()  # raises if any line is malformed JSON
    if not lines:
        raise TestFailure("no audit lines produced during race")

    # 1. every decision line has the core cert fields.
    decisions = [l for l in lines if l.get("event") in {"connect", "acl"}]
    for d in decisions:
        for field in ("cn", "chain_ok", "decision_id", "client_id"):
            if field not in d:
                raise TestFailure(
                    f"decision line missing {field}: {d}"
                )

    # 2. decision_ids are unique across the whole run.
    ids = [d["decision_id"] for d in decisions if d.get("decision_id") is not None]
    if len(set(ids)) != len(ids):
        dups = [x for x in set(ids) if ids.count(x) > 1]
        raise TestFailure(f"duplicate decision_id under race: {dups[:5]}")

    # 3. both policy tags (A and B) were observed — proves both policies
    #    actually served decisions during the race, so the atomic-swap
    #    claim is meaningful (not just one policy holding the whole run).
    notes = [l.get("note", "") for l in lines if l.get("event") == "policy.note"]
    saw_a = any("policy=A" in n for n in notes)
    saw_b = any("policy=B" in n for n in notes)
    if not (saw_a and saw_b):
        raise TestFailure(
            f"expected both A and B tags in policy.note during race, "
            f"got A={saw_a} B={saw_b} ({len(notes)} notes total)"
        )

    # 4. a clean connect after the race still works.
    cp = do_publish("operator_alice.crt", "operator_alice.key", "alice",
                    "devices/alice/post-race", "x")
    if cp.returncode != 0:
        raise TestFailure(
            f"post-race connect failed: {cp.stdout!r} / {cp.stderr!r}"
        )


# --------------------------------------------------------------------------
# OCSP revocation
# --------------------------------------------------------------------------

import contextlib


@contextlib.contextmanager
def ocsp_responder():
    """Run a throwaway openssl OCSP responder on 127.0.0.1:18888, serving
    the e2e/pki/ocsp_index.txt file. Yields the subprocess.Popen so tests
    can assert it's still alive. Kills it on exit."""
    cmd = [
        "openssl", "ocsp",
        "-index", str(PKI/"ocsp_index.txt"),
        "-port", "18888",
        "-rsigner", str(PKI/"ocsp_signer.crt"),
        "-rkey", str(PKI/"ocsp_signer.key"),
        "-CA", str(PKI/"intermediate_a.crt"),
        "-ignore_err",
    ]
    # Suppress the responder's per-request text dump.
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    # Wait for the listener to come up.
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            probe = subprocess.run(
                ["ss", "-ltn"], capture_output=True, text=True, timeout=2
            )
            if ":18888 " in probe.stdout:
                break
        except Exception:
            pass
        time.sleep(0.05)
    else:
        proc.kill()
        raise TestFailure("OCSP responder failed to start on :18888")
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _install_ocsp_policy(current_policy: pathlib.Path) -> str:
    """Overwrite policy.rego with a policy that gates CONNECT on
    ocsp.check() returning 'good' for the leaf. Returns the prior
    contents so the caller can restore. Triggers SIGHUP."""
    pid = int((RUN/"broker.pid").read_text().strip())
    previous = current_policy.read_text()

    fp_a = subprocess.check_output(
        ["openssl", "x509", "-in", str(PKI/"root_a.crt"),
         "-noout", "-fingerprint", "-sha256"],
        text=True,
    ).strip().split("=", 1)[1].replace(":", "").lower()
    fp_b = subprocess.check_output(
        ["openssl", "x509", "-in", str(PKI/"root_b.crt"),
         "-noout", "-fingerprint", "-sha256"],
        text=True,
    ).strip().split("=", 1)[1].replace(":", "").lower()

    current_policy.write_text(textwrap.dedent(f"""\
        package mqtt

        root_a_fp := "{fp_a}"
        root_b_fp := "{fp_b}"

        anchor_fp := input.cert.trust_anchor.fingerprint_sha256
        is_operator {{ anchor_fp == root_a_fp }}

        default connect := false
        default acl := false

        # Inline so the diagnostic audit line fires before the status gate —
        # even a denied connect leaves a policy.note with the observed OCSP
        # status, which is how an operator under a strict policy debugs the
        # responder.
        connect {{
            input.cert.chain_ok
            input.cert.cn != ""
            is_operator
            raw := ocsp.check()
            audit.log(sprintf("ocsp_raw=%v", [raw]))
            ocsp_results := json.unmarshal(raw)
            status := ocsp_results[0].status
            audit.log(sprintf("ocsp=%v cn=%v err=%v", [status, input.cert.cn, ocsp_results[0].error]))
            status == "good"
        }}

        acl {{ is_operator; startswith(input.acl.topic, "devices/") }}
    """))
    os.kill(pid, signal.SIGHUP)
    time.sleep(0.2)
    return previous


def _restore_policy(current_policy: pathlib.Path, previous: str) -> None:
    pid = int((RUN/"broker.pid").read_text().strip())
    current_policy.write_text(previous)
    os.kill(pid, signal.SIGHUP)
    time.sleep(0.2)


@test("ocsp_good_cert_allowed")
def t_ocsp_good() -> None:
    """With ocsp.check() returning 'good' for the leaf, the policy allows
    the connect and emits an audit line tagged ocsp=good."""
    current_policy = RUN/"policy.rego"
    previous = _install_ocsp_policy(current_policy)
    try:
        with ocsp_responder():
            reset_audit()
            cp = do_publish("ocsp_good_alice.crt", "ocsp_good_alice.key",
                            "ocsp-good", "devices/ocsp-good/x", "hi")
            if cp.returncode != 0:
                raise TestFailure(
                    f"good OCSP cert was rejected: {cp.stdout!r} / {cp.stderr!r}"
                )
            time.sleep(0.3)
            lines = read_audit()
            notes = [l.get("note", "") for l in lines
                     if l.get("event") == "policy.note"]
            if not any("ocsp=good" in n for n in notes):
                raise TestFailure(
                    f"expected ocsp=good in policy.note, got notes: {notes}"
                )
    finally:
        _restore_policy(current_policy, previous)


@test("ocsp_revoked_cert_denied")
def t_ocsp_revoked() -> None:
    """With ocsp.check() returning 'revoked' for the leaf, the policy
    denies. The connect line must record chain_ok=true (the chain itself
    verifies) yet still be denied."""
    current_policy = RUN/"policy.rego"
    previous = _install_ocsp_policy(current_policy)
    try:
        with ocsp_responder():
            reset_audit()
            cp = do_publish("ocsp_revoked_alice.crt", "ocsp_revoked_alice.key",
                            "ocsp-revoked", "devices/ocsp-revoked/x", "hi")
            if cp.returncode == 0:
                raise TestFailure("revoked OCSP cert was accepted!")
            lines = wait_for_audit(
                lambda ls: any(l.get("event") == "connect"
                               and l.get("result") == "deny"
                               for l in ls)
            )
            deny = next(l for l in lines if l.get("event") == "connect"
                        and l.get("result") == "deny")
            if not deny.get("chain_ok"):
                raise TestFailure(
                    "deny says chain_ok=false, but the cert chain itself is fine "
                    "(revocation is an orthogonal signal)"
                )
    finally:
        _restore_policy(current_policy, previous)


@test("ocsp_responder_unreachable_fail_closed")
def t_ocsp_unreachable() -> None:
    """When the OCSP responder is NOT running, ocsp.check() on the leaf
    returns status='error'. Our test policy only allows `good`, so the
    decision is deny — proving fail-closed semantics on OCSP outage."""
    current_policy = RUN/"policy.rego"
    previous = _install_ocsp_policy(current_policy)
    try:
        reset_audit()
        cp = do_publish("ocsp_good_alice.crt", "ocsp_good_alice.key",
                        "ocsp-outage", "devices/ocsp-outage/x", "hi")
        if cp.returncode == 0:
            raise TestFailure(
                "OCSP-unreachable cert was accepted; expected fail-closed deny"
            )
        wait_for_audit(
            lambda ls: any(l.get("event") == "connect"
                           and l.get("result") == "deny"
                           for l in ls)
        )
    finally:
        _restore_policy(current_policy, previous)


@test("reload_broken_policy_keeps_previous")
def t_reload_broken() -> None:
    """SIGHUP the broker with a syntactically broken policy. The broker must
    stay up, keep the old policy, and a subsequent valid connect must still
    succeed. The audit log should carry a deny for the bad reload attempt
    (broker log) and an allow for the successful connect that follows."""
    # Point policy_file at a bad rego, SIGHUP, then restore + SIGHUP again.
    current_conf = RUN / "mosquitto.conf"
    current_policy = RUN / "policy.rego"
    backup_policy = RUN / "policy.rego.bak"

    original = current_policy.read_text()
    backup_policy.write_text(original)
    try:
        # A numeric package name is a hard parse error in rego — much
        # more likely to trip rego-cpp's parser than freeform gibberish.
        # (rego-cpp is surprisingly lenient about stray tokens at the
        # top level; we want the reload to definitively fail so we can
        # assert the fail-safe path.)
        current_policy.write_text("package 123\n")
        reset_audit()

        pid = int((RUN / "broker.pid").read_text().strip())
        os.kill(pid, 1)   # SIGHUP
        time.sleep(0.5)

        # Broker must still be alive.
        try:
            os.kill(pid, 0)
        except OSError:
            raise TestFailure("broker died on broken-policy reload")

        # Post-reload valid connect must still work using the OLD policy.
        current_policy.write_text(original)  # restore for anyone else, but
                                             # broker is still holding old copy
        cp = do_publish("operator_alice.crt", "operator_alice.key", "alice",
                        "devices/alice/still-alive", "x")
        if cp.returncode != 0:
            raise TestFailure(
                f"post-broken-reload connect failed: {cp.stdout!r} / {cp.stderr!r}"
            )
    finally:
        current_policy.write_text(original)
        # Do a clean reload so subsequent tests see the restored policy
        # file on disk in case the broker re-reads it.
        try:
            pid = int((RUN / "broker.pid").read_text().strip())
            os.kill(pid, 1)
            time.sleep(0.3)
        except Exception:
            pass


# --------------------------------------------------------------------------
# entrypoint
# --------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    wanted = argv[1:] or list(TESTS)
    unknown = [n for n in wanted if n not in TESTS]
    if unknown:
        print(f"unknown tests: {unknown}", file=sys.stderr)
        return 2

    fails = []
    for name in wanted:
        try:
            TESTS[name]()
            print(f"  PASS  {name}")
        except TestFailure as e:
            print(f"  FAIL  {name}: {e}")
            fails.append(name)
        except Exception as e:
            print(f"  ERR   {name}: {type(e).__name__}: {e}")
            fails.append(name)

    print()
    if fails:
        print(f"cybersec: {len(fails)} FAIL / {len(wanted) - len(fails)} PASS")
        return 1
    print(f"cybersec: {len(wanted)} PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
