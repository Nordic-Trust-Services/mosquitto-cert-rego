#!/usr/bin/env python3
# Copyright (c) 2026 Cedalo Ltd
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
"""
Reference MQTT client for the mosquitto cert-rego plugin.

Connects to a broker using mutual TLS with a client certificate. The plugin
is passwordless: it authenticates clients by their certificate alone and
uses a Rego policy to decide allow/deny. Authorisation attributes come
from the cert fields, the trust anchor the chain verified against, and
any services the policy chooses to call (LDAP, HTTP/OAuth2, etc.).

Exit codes:
    0  success
    1  auth denied by broker (Rego policy said no, or OCSP revoked)
    2  TLS handshake failed (cert not trusted by broker, or expired)
    3  network / timeout / unreachable
    4  configuration error (missing file, bad arg, etc.)
    5  unexpected MQTT protocol / library error
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Optional

try:
    import paho.mqtt.client as mqtt
    from paho.mqtt.enums import CallbackAPIVersion, MQTTErrorCode
    from paho.mqtt.reasoncodes import ReasonCode
except ImportError:
    sys.stderr.write(
        "paho-mqtt is required. Install with: pip install 'paho-mqtt>=2.0'\n"
    )
    sys.exit(4)


# ---- exit codes --------------------------------------------------------

EXIT_OK = 0
EXIT_AUTH_DENIED = 1
EXIT_TLS_FAILED = 2
EXIT_NETWORK = 3
EXIT_CONFIG = 4
EXIT_PROTOCOL = 5


# ---- connection outcome tracking ---------------------------------------

@dataclass
class Outcome:
    """Passed to callbacks so the main thread can read the final result."""
    connected: bool = False
    exit_code: int = EXIT_PROTOCOL
    message: str = ""
    subscribed: bool = False
    published: bool = False


def _reason_code_to_exit(rc: ReasonCode) -> int:
    """
    Map MQTT v5 CONNACK reason codes to shell-friendly exit codes.

    The plugin returns MOSQ_ERR_AUTH for all Rego denials and OCSP
    revocations; the broker surfaces that as reason code 135 (NotAuthorized)
    or 134 (BadUserNameOrPassword) depending on the auth path. We collapse
    both to EXIT_AUTH_DENIED because from the caller's perspective they
    mean the same thing: the broker refused this identity.
    """
    v = int(rc.value)
    if v == 0:
        return EXIT_OK
    # MQTT v5 reason codes (§2.2.2.2)
    if v in (
        0x87,  # Not authorized
        0x86,  # Bad username or password
        0x8c,  # Bad authentication method
        0x95,  # Packet too large (not strictly an auth issue, but rare here)
        0x9a,  # Retain not supported (irrelevant, but ReasonCode is wide)
    ):
        return EXIT_AUTH_DENIED
    if v == 0x88:  # Server unavailable
        return EXIT_NETWORK
    return EXIT_PROTOCOL


# ---- callbacks ---------------------------------------------------------

def on_connect(
    client: mqtt.Client,
    userdata: Outcome,
    flags: dict,
    reason_code: ReasonCode,
    properties: Optional[object],
) -> None:
    logging.debug("CONNACK flags=%s reason_code=%s", flags, reason_code)
    userdata.connected = reason_code.is_failure is False
    if userdata.connected:
        userdata.exit_code = EXIT_OK
        userdata.message = "connected"
        logging.info("Connected to broker")
    else:
        userdata.exit_code = _reason_code_to_exit(reason_code)
        userdata.message = f"broker refused connection: {reason_code}"
        logging.error("%s", userdata.message)


def on_disconnect(
    client: mqtt.Client,
    userdata: Outcome,
    flags: dict,
    reason_code: ReasonCode,
    properties: Optional[object],
) -> None:
    logging.debug("DISCONNECT reason_code=%s flags=%s", reason_code, flags)
    # If we never managed to connect, this disconnect is the broker's way of
    # reporting the auth failure — propagate the reason code.
    if not userdata.connected and userdata.exit_code == EXIT_OK:
        userdata.exit_code = _reason_code_to_exit(reason_code)
        userdata.message = f"disconnected before connect acknowledged: {reason_code}"


def on_subscribe(
    client: mqtt.Client,
    userdata: Outcome,
    mid: int,
    reason_codes: list,
    properties: Optional[object],
) -> None:
    logging.debug("SUBACK mid=%s reason_codes=%s", mid, reason_codes)
    for rc in reason_codes:
        if rc.is_failure:
            # The plugin's ACL callback denied the subscription.
            userdata.exit_code = EXIT_AUTH_DENIED
            userdata.message = f"subscribe denied: {rc}"
            logging.error("%s", userdata.message)
            client.disconnect()
            return
    userdata.subscribed = True
    logging.info("Subscribed")


def on_message(
    client: mqtt.Client,
    userdata: Outcome,
    msg: mqtt.MQTTMessage,
) -> None:
    try:
        payload = msg.payload.decode("utf-8")
    except UnicodeDecodeError:
        payload = repr(msg.payload)
    sys.stdout.write(f"{msg.topic} {payload}\n")
    sys.stdout.flush()


def on_publish(
    client: mqtt.Client,
    userdata: Outcome,
    mid: int,
    reason_code: ReasonCode,
    properties: Optional[object],
) -> None:
    logging.debug("PUBACK mid=%s reason_code=%s", mid, reason_code)
    if reason_code.is_failure:
        # The plugin's ACL callback denied the publish.
        userdata.exit_code = EXIT_AUTH_DENIED
        userdata.message = f"publish denied: {reason_code}"
        logging.error("%s", userdata.message)
        return
    userdata.published = True


# ---- TLS setup ---------------------------------------------------------

def _read_file(path: str, what: str) -> None:
    """Fail fast with a clear message if a required file can't be read."""
    if not os.path.isfile(path):
        raise SystemExit(f"{what}: file not found: {path}")
    if not os.access(path, os.R_OK):
        raise SystemExit(f"{what}: file not readable: {path}")


def configure_tls(
    client: mqtt.Client,
    ca_file: str,
    client_cert: str,
    client_key: str,
    insecure: bool,
    server_hostname: Optional[str] = None,
) -> None:
    """
    Configure TLS on the client using the broker's CA bundle and our own
    client cert+key.

    If `insecure` is True we disable hostname verification — only useful
    for local testing against a broker cert whose CN doesn't match the
    hostname we happen to be connecting to.
    """
    _read_file(ca_file, "ca_file")
    _read_file(client_cert, "client_cert")
    _read_file(client_key, "client_key")

    # Build the SSLContext by hand so we can set the minimum version and
    # disable hostname check only when the caller asks. paho's tls_set()
    # convenience wrapper works too but doesn't expose min_version.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca_file)
    ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = not insecure
    if server_hostname:
        # paho doesn't take a separate SNI hint, so we stash the hostname
        # here and set server_hostname via SSLContext later via tls_insecure_set
        # isn't quite right — easier path: paho.tls_set_context() then
        # a regular connect() with the provided host as SNI.
        pass
    client.tls_set_context(ctx)
    if insecure:
        client.tls_insecure_set(True)


# ---- main --------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cert_rego_client",
        description=(
            "Reference MQTT client for the mosquitto cert-rego plugin. "
            "Connects via mTLS and optionally publishes, subscribes, or "
            "just smoke-tests the connection."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples

  # Smoke test: just connect and disconnect, exit 0 if the plugin allows us.
  cert_rego_client --host broker --port 8883 \\
      --ca /etc/mosquitto/ca/root.pem \\
      --cert /etc/mosquitto/clients/alice.crt \\
      --key  /etc/mosquitto/clients/alice.key \\
      connect

  # Publish a single message.
  cert_rego_client --host broker --port 8883 \\
      --ca root.pem --cert alice.crt --key alice.key \\
      publish --topic devices/alice/status --message '{"online":true}'

  # Subscribe for 5 seconds, print every message to stdout, then exit.
  cert_rego_client --host broker --port 8883 \\
      --ca root.pem --cert alice.crt --key alice.key \\
      subscribe --topic 'devices/alice/#' --timeout 5
""",
    )
    # Connection args
    p.add_argument("--host", required=True, help="broker host / address")
    p.add_argument("--port", type=int, default=8883, help="broker TLS port")
    p.add_argument("--client-id", default="", help="MQTT client id (default: random)")
    p.add_argument("--keepalive", type=int, default=60, help="MQTT keepalive")
    p.add_argument(
        "--protocol-version",
        type=int,
        choices=(4, 5),
        default=5,
        help="MQTT protocol version (4 = 3.1.1, 5 = v5). "
        "The plugin works with both; v5 gives you richer reason codes.",
    )

    # TLS args
    p.add_argument("--ca", required=True, help="CA bundle to verify broker cert")
    p.add_argument("--cert", required=True, help="client certificate (PEM)")
    p.add_argument("--key", required=True, help="client private key (PEM)")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="skip hostname verification on broker cert (testing only)",
    )

    # The CONNECT username is forwarded to the plugin's Rego input as
    # input.connect.username — policies may read it, but since the plugin
    # is passwordless there is no corresponding --password argument.
    p.add_argument(
        "--username",
        help="MQTT CONNECT username (exposed to policy as input.connect.username)",
    )

    # Logging
    p.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="increase logging (-v info, -vv debug)",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sp_connect = sub.add_parser(
        "connect",
        help="connect, then disconnect — use as an auth smoke test",
    )
    sp_connect.add_argument(
        "--hold-seconds",
        type=float,
        default=0.5,
        help="how long to stay connected before disconnecting",
    )

    sp_pub = sub.add_parser("publish", help="publish a single message")
    sp_pub.add_argument("--topic", required=True)
    sp_pub.add_argument("--message", required=True)
    sp_pub.add_argument("--qos", type=int, choices=(0, 1, 2), default=1)
    sp_pub.add_argument("--retain", action="store_true")

    sp_sub = sub.add_parser("subscribe", help="subscribe, print messages, then exit")
    sp_sub.add_argument("--topic", required=True, help="topic filter")
    sp_sub.add_argument("--qos", type=int, choices=(0, 1, 2), default=1)
    sp_sub.add_argument(
        "--timeout",
        type=float,
        default=0,
        help="exit after N seconds. 0 = run until Ctrl-C",
    )

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # logging
    level = {0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    # Build the paho client.
    protocol = mqtt.MQTTv5 if args.protocol_version == 5 else mqtt.MQTTv311
    outcome = Outcome()
    try:
        client = mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=args.client_id,
            userdata=outcome,
            protocol=protocol,
        )
    except Exception as ex:
        logging.error("failed to construct MQTT client: %s", ex)
        return EXIT_PROTOCOL

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.on_publish = on_publish

    if args.username is not None:
        # Passwordless: we only set the username so policies can read
        # input.connect.username. Password is intentionally never sent.
        client.username_pw_set(args.username, None)

    try:
        configure_tls(client, args.ca, args.cert, args.key, args.insecure)
    except SystemExit as ex:
        logging.error("%s", ex)
        return EXIT_CONFIG
    except ssl.SSLError as ex:
        logging.error("TLS setup failed: %s", ex)
        return EXIT_TLS_FAILED

    # Connect. The CONNECT packet itself does not fail synchronously — the
    # outcome arrives in on_connect or on_disconnect via a reason code.
    try:
        client.connect(args.host, args.port, keepalive=args.keepalive)
    except ssl.SSLCertVerificationError as ex:
        logging.error("broker cert verification failed: %s", ex)
        return EXIT_TLS_FAILED
    except (socket.gaierror, socket.timeout, OSError) as ex:
        logging.error("network error: %s", ex)
        return EXIT_NETWORK

    client.loop_start()

    # Wait up to 10s for CONNACK / DISCONNECT. Once on_connect fires,
    # outcome.connected is True or outcome.exit_code is non-zero.
    deadline = time.time() + 10
    while time.time() < deadline:
        if outcome.connected or outcome.exit_code != EXIT_PROTOCOL:
            break
        time.sleep(0.05)
    else:
        logging.error("timeout waiting for CONNACK from %s:%d", args.host, args.port)
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass
        return EXIT_NETWORK

    if not outcome.connected:
        client.loop_stop()
        return outcome.exit_code

    # Dispatch on subcommand.
    rc = EXIT_OK
    try:
        if args.cmd == "connect":
            time.sleep(max(0.0, args.hold_seconds))

        elif args.cmd == "publish":
            info = client.publish(
                args.topic, args.message, qos=args.qos, retain=args.retain,
            )
            # For qos>0 we wait for the PUBACK (or a denial).
            if args.qos > 0:
                info.wait_for_publish(timeout=5.0)
            else:
                # qos 0: nothing comes back. The plugin's ACL denial path
                # just drops the message server-side. Give it a moment to
                # settle and hope — documented, intentional limitation.
                time.sleep(0.2)
            if outcome.exit_code != EXIT_OK:
                rc = outcome.exit_code

        elif args.cmd == "subscribe":
            client.subscribe(args.topic, qos=args.qos)
            # Wait for SUBACK or a deny disconnect.
            t0 = time.time()
            while not outcome.subscribed and outcome.exit_code == EXIT_OK \
                    and (time.time() - t0) < 5.0:
                time.sleep(0.05)
            if outcome.exit_code != EXIT_OK:
                rc = outcome.exit_code
            else:
                if args.timeout > 0:
                    time.sleep(args.timeout)
                else:
                    try:
                        while True:
                            time.sleep(1.0)
                    except KeyboardInterrupt:
                        logging.info("Ctrl-C, exiting")
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        client.loop_stop()

    return rc


if __name__ == "__main__":
    sys.exit(main())
