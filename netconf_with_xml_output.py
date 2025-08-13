#!/usr/bin/env python3
# netconf_iosxe_fancy_ascii.py
#
# Narrated NETCONF workflow for Cisco IOS-XE (ASCII-only, color optional).
# - Preflights TCP 830/22, connects to the first that works
# - Uses tuple-form filters for <get>/<get-config> so namespaces are correct
# - For edit-config, provides a properly namespaced <config> wrapper
# - Uses candidate if available; otherwise writes to running
# - APPLY: sets hostname + creates Loopback; REVERT: restores hostname + removes Loopback
# - XML printing is ON by default and pretty-printed; disable with: --xml off
# - NEW: Script now prints the OUTGOING <config> XML payload before edit-config
#
# Works with older ncclient: avoids banner_timeout/auth_timeout/keepalive kwargs.
# Keepalive is set via m.session.set_keepalive(30) after connecting.

import argparse
import re
import socket
import sys
import time
from contextlib import closing

from ncclient import manager
from ncclient.operations import RPCError
from ncclient.transport.errors import SSHError, SessionCloseError
from ncclient.xml_ import XMLError

# ------------------- Pretty printing helpers -------------------

def _supports_color():
    return sys.stderr.isatty()

class C:
    if _supports_color():
        RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
        RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"
        MAGENTA="\033[35m"; CYAN="\033[36m"; GRAY="\033[90m"
    else:
        RESET=""; BOLD=""; DIM=""
        RED=""; GREEN=""; YELLOW=""; BLUE=""
        MAGENTA=""; CYAN=""; GRAY=""

# ASCII-only icons
ICON = {
    "section": "[SEC]",
    "preflight": "[NET]",
    "connect": "[SSH]",
    "caps": "[CAP]",
    "plan": "[PLAN]",
    "get": "[GET]",
    "lock": "[LOCK]",
    "edit": "[EDIT]",
    "commit": "[COMMIT]",
    "unlock": "[UNLOCK]",
    "persist": "[SAVE]",
    "verify": "[CHECK]",
    "done": "[DONE]",
    "ok": "[OK]",
    "warn": "[WARN]",
    "fail": "[FAIL]",
    "info": "[INFO]",
}

def _pretty_xml(xml_text, indent="  "):
    """Return pretty-printed XML; fall back to raw on parse errors."""
    try:
        from xml.dom import minidom
        xml_str = xml_text.lstrip()
        dom = minidom.parseString(xml_str.encode("utf-8") if isinstance(xml_str, str) else xml_str)
        pretty = dom.toprettyxml(indent=indent, encoding="utf-8").decode("utf-8")
        lines = [ln for ln in pretty.splitlines() if ln.strip()]
        return "\n".join(lines)
    except Exception:
        return xml_text

class Printer:
    def __init__(self, enable_color=True, show_xml=True):
        self.step_no = 0
        self.enable_color = enable_color and _supports_color()
        self.show_xml = show_xml

    def _color(self, text, color):
        if not self.enable_color: return text
        return f"{color}{text}{C.RESET}"

    def _fmt_step(self, label, emoji, title):
        self.step_no += 1
        return f"{self._color(f'[Step {self.step_no:02d}]', C.BLUE)} {emoji} {self._color(label, C.BOLD)} - {title}"

    def section(self, title):
        print(f"\n{self._color('-'*80, C.GRAY)}")
        print(f"{ICON['section']}  {self._color(title, C.BOLD)}")
        print(f"{self._color('-'*80, C.GRAY)}")

    def step(self, label, emoji, title):
        print(self._fmt_step(label, emoji, title))

    def info(self, msg):
        print(f"  {ICON['info']}  {msg}")

    def ok(self, msg="OK"):
        print(f"  {self._color(ICON['ok'] + ' ' + msg, C.GREEN)}")

    def warn(self, msg):
        print(f"  {self._color(ICON['warn'] + ' ' + msg, C.YELLOW)}")

    def fail(self, msg):
        print(f"  {self._color(ICON['fail'] + ' ' + msg, C.RED)}")

    def xml(self, xml_text, max_chars=4000, header="XML"):
        if not self.show_xml:
            self.info("(XML suppressed; run with --xml on to print replies)")
            return
        pretty = _pretty_xml(xml_text)
        trimmed = pretty if len(pretty) <= max_chars else (pretty[:max_chars] + "\n... [truncated]")
        print(self._color(f"  -- {header} (pretty) -----------------------------------------------", C.GRAY))
        for line in trimmed.splitlines():
            print(self._color("  | ", C.GRAY) + line)
        print(self._color("  --------------------------------------------------------------------", C.GRAY))

# ------------------- Network / NETCONF helpers -------------------

def port_open(host, port, timeout=3):
    try:
        with closing(socket.create_connection((host, port), timeout=timeout)):
            return True
    except OSError:
        return False

def try_connect(host, ports, username, password, p: Printer):
    last_exc = None
    for pnum in ports:
        p.step("Preflight", ICON["preflight"], f"Checking TCP reachability to {host}:{pnum}")
        if not port_open(host, pnum):
            p.warn(f"TCP {host}:{pnum} is CLOSED")
            continue
        p.ok(f"TCP {host}:{pnum} is OPEN")
        p.step("Connect", ICON["connect"], f"Attempt NETCONF over SSH to {host}:{pnum}")
        try:
            t0 = time.perf_counter()
            m = manager.connect(
                host=host,
                port=pnum,
                username=username,
                password=password,
                hostkey_verify=False,
                allow_agent=False,
                look_for_keys=False,
                timeout=60,  # legacy-safe only
            )
            dt = time.perf_counter() - t0
            p.ok(f"NETCONF SSH connect success on port {pnum} ({dt:.2f}s)")
            return m, pnum
        except (SessionCloseError, SSHError) as e:
            p.fail(f"Session failed on port {pnum}: {type(e).__name__}: {e}")
            last_exc = e
        except Exception as e:
            p.fail(f"Unexpected failure on port {pnum}: {type(e).__name__}: {e}")
            last_exc = e
    if last_exc:
        raise last_exc
    raise RuntimeError("No open ports found for NETCONF (830/22).")

def read_hostname(m):
    hostname_filter = """
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
      <hostname/>
    </native>
    """
    reply = m.get_config(source="running", filter=("subtree", hostname_filter))
    xml = reply.xml
    m_ = re.search(r"<hostname>([^<]+)</hostname>", xml)
    return reply.xml, (m_.group(1).strip() if m_ else "")

def verify_state(m, loop_id):
    verify_filter = f"""
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
      <hostname/>
      <interface>
        <Loopback>
          <name>{loop_id}</name>
        </Loopback>
      </interface>
    </native>
    """
    reply = m.get_config(source="running", filter=("subtree", verify_filter))
    return reply.xml

def do_apply(m, p: Printer, target_ds, new_hostname, loop_id, has_candidate):
    edit_payload = f"""
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <hostname>{new_hostname}</hostname>
        <interface>
          <Loopback>
            <name>{loop_id}</name>
            <description>added via NETCONF</description>
            <ip>
              <address>
                <primary>
                  <address>10.99.99.1</address>
                  <mask>255.255.255.255</mask>
                </primary>
              </address>
            </ip>
          </Loopback>
        </interface>
      </native>
    </config>
    """
    p.step("Lock", ICON["lock"], f"Locking datastore: {target_ds}")
    m.lock(target=target_ds)
    try:
        p.step("Edit", ICON["edit"], f"edit-config (target={target_ds}) - set hostname and add Loopback{loop_id}")
        # NEW: Show exactly what we are sending in the <config> body
        p.info("Outgoing edit-config <config> payload:")
        p.xml(edit_payload, header="Outgoing <config>")
        t0 = time.perf_counter()
        m.edit_config(target=target_ds, config=edit_payload, default_operation="merge")
        p.ok(f"edit-config applied ({time.perf_counter() - t0:.2f}s)")
        if has_candidate:
            p.step("Commit", ICON["commit"], "Commit candidate to running")
            t1 = time.perf_counter()
            m.commit()
            p.ok(f"commit OK ({time.perf_counter() - t1:.2f}s)")
    finally:
        p.step("Unlock", ICON["unlock"], f"Unlocking datastore: {target_ds}")
        m.unlock(target=target_ds)
        p.ok("Unlocked")

def do_revert(m, p: Printer, target_ds, revert_hostname, loop_id, has_candidate):
    edit_payload = f"""
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <hostname>{revert_hostname}</hostname>
        <interface>
          <Loopback nc:operation="remove">
            <name>{loop_id}</name>
          </Loopback>
        </interface>
      </native>
    </config>
    """
    p.step("Lock", ICON["lock"], f"Locking datastore: {target_ds}")
    m.lock(target=target_ds)
    try:
        p.step("Edit", ICON["edit"], f"edit-config (REVERT target={target_ds}) - restore hostname and remove Loopback{loop_id}")
        # NEW: Show exactly what we are sending in the <config> body (revert)
        p.info("Outgoing edit-config <config> payload (REVERT):")
        p.xml(edit_payload, header="Outgoing <config> (revert)")
        t0 = time.perf_counter()
        m.edit_config(target=target_ds, config=edit_payload, default_operation="merge")
        p.ok(f"revert edit-config applied ({time.perf_counter() - t0:.2f}s)")
        if has_candidate:
            p.step("Commit", ICON["commit"], "Commit candidate to running")
            t1 = time.perf_counter()
            m.commit()
            p.ok(f"commit OK ({time.perf_counter() - t1:.2f}s)")
    finally:
        p.step("Unlock", ICON["unlock"], f"Unlocking datastore: {target_ds}")
        m.unlock(target=target_ds)
        p.ok("Unlocked")

# ------------------- Main -------------------

def main():
    parser = argparse.ArgumentParser(description="IOS-XE NETCONF apply/revert/show with step-by-step logs (ASCII icons, pretty XML)")
    parser.add_argument("--host", default="192.168.122.2", help="Router IP or hostname (default: 192.168.122.2)")
    parser.add_argument("--user", default="ineuser", help="Username (default: ineuser)")
    parser.add_argument("--password", default="ine123", help="Password (default: ine123)")
    parser.add_argument("--action", choices=["apply", "revert", "show"], default="apply",
                        help="Action to perform (default: apply)")
    parser.add_argument("--hostname", default="NETCONF-DEMO",
                        help="Hostname to set on APPLY (default: NETCONF-DEMO)")
    parser.add_argument("--revert-hostname", default=None,
                        help="Hostname to restore on REVERT (default: current running hostname)")
    parser.add_argument("--loopback", type=int, default=99, help="Loopback ID to manage (default: 99)")
    parser.add_argument("--iface", default="GigabitEthernet1", help="Interface name for GET oper (default: GigabitEthernet1)")
    parser.add_argument("--xml", choices=["on","off"], default="on",
                        help="Print XML replies (pretty) (default: on)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--ports", default="830,22", help="Port order to try (csv, default: 830,22)")
    parser.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    parser.add_argument("--debug", action="store_true", help="Enable ncclient/paramiko DEBUG logging to stdout")
    args = parser.parse_args()

    if args.debug:
        import logging
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    p = Printer(enable_color=not args.no_color, show_xml=(args.xml == "on"))

    # Banner
    p.section("IOS-XE NETCONF Orchestrator")
    p.step("Plan", ICON["plan"], "Inputs and Environment")
    p.info(f"Host: {args.host}")
    p.info(f"User: {args.user}")
    p.info(f"Action: {args.action}")
    p.info(f"Hostname (apply): {args.hostname}")
    p.info(f"Loopback ID: {args.loopback}")
    p.info(f"Operational GET interface: {args.iface}")
    p.info(f"Port order: {args.ports}")
    if not args.yes and args.action in ("apply", "revert"):
        p.info("Press Enter to proceed or Ctrl+C to abort...")
        try:
            input()
        except KeyboardInterrupt:
            p.warn("Aborted by user.")
            sys.exit(1)

    ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]

    # Connect
    try:
        m, used_port = try_connect(args.host, ports, args.user, args.password, p)
    except Exception as e:
        p.section("Connection Failure")
        p.fail(f"Could not establish NETCONF over SSH: {type(e).__name__}: {e}")
        p.info("Ensure 'netconf-yang' is configured, VTY allows SSH with 'login local', and ACL/VRF is not blocking.")
        sys.exit(1)

    # Keepalive (legacy-friendly)
    try:
        m.session.set_keepalive(30)
        p.ok("Keepalive set to 30s")
    except Exception:
        p.warn("Keepalive not supported by session (safe to ignore)")

    # Capabilities
    p.section("Server Capabilities")
    caps = list(m.server_capabilities)
    has_candidate = any(":candidate" in c for c in caps)
    has_startup   = any(":startup"   in c for c in caps)
    target_ds     = "candidate" if has_candidate else "running"
    p.step("Caps", ICON["caps"], f"Datastores: candidate={has_candidate}, startup={has_startup} (port used: {used_port})")
    for i, c in enumerate(caps[:10], 1):
        p.info(f"{i:2d}. {c}")

    # GET oper (may be empty)
    p.section("Operational Data (GET)")
    has_cisco_oper = any("Cisco-IOS-XE-interfaces-oper" in c for c in caps)
    if has_cisco_oper:
        oper_filter = f"""
        <interfaces-oper-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">
          <interface-oper>
            <name>{args.iface}</name>
          </interface-oper>
        </interfaces-oper-data>
        """
        p.step("GET", ICON["get"], f"Cisco oper model for {args.iface}")
        try:
            reply = m.get(filter=("subtree", oper_filter))
            p.ok("RPC OK")
            p.xml(reply.xml)
        except RPCError as e:
            p.warn(f"GET (Cisco oper) RPCError: {e}")
    else:
        ietf_state = f"""
        <interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces">
          <interface>
            <name>{args.iface}</name>
          </interface>
        </interfaces-state>
        """
        p.step("GET", ICON["get"], f"IETF interfaces-state for {args.iface}")
        try:
            reply = m.get(filter=("subtree", ietf_state))
            p.ok("RPC OK")
            p.xml(reply.xml)
        except RPCError as e:
            p.warn(f"GET (interfaces-state) RPCError: {e}")

    # Show current hostname
    p.section("Current Hostname")
    try:
        xml, curr_hostname = read_hostname(m)
        p.ok(f"Hostname: {curr_hostname or '(not found)'}")
        p.xml(xml, max_chars=2000)
    except RPCError as e:
        p.warn(f"GET-CONFIG hostname failed: {e}")
        curr_hostname = ""

    # Perform action
    if args.action == "show":
        p.section("Show-Only Mode")
        p.info("No changes made.")
        p.step("Done", ICON["done"], "Closing session")
        m.close_session()
        p.ok("Session closed")
        return

    if args.action == "apply":
        p.section("APPLY Changes")
        try:
            do_apply(m, p, target_ds, args.hostname, args.loopback, has_candidate)
        except (RPCError, XMLError) as e:
            p.fail(f"APPLY failed: {type(e).__name__}: {e}")
            m.close_session()
            sys.exit(2)
        # Verify
        p.step("Verify", ICON["verify"], "Reading back running-config to confirm changes")
        try:
            xml = verify_state(m, args.loopback)
            p.ok("Verification RPC OK")
            p.xml(xml, max_chars=4000)
        except RPCError as e:
            p.warn(f"VERIFY RPCError: {e}")

    if args.action == "revert":
        p.section("REVERT Changes")
        revert_hostname = args.revert_hostname or curr_hostname or "CSR-XE"
        p.info(f"Reverting to hostname: {revert_hostname} and removing Loopback{args.loopback}")
        try:
            do_revert(m, p, target_ds, revert_hostname, args.loopback, has_candidate)
        except (RPCError, XMLError) as e:
            p.fail(f"REVERT failed: {type(e).__name__}: {e}")
            m.close_session()
            sys.exit(3)
        # Verify
        p.step("Verify", ICON["verify"], "Reading back running-config to confirm reversion")
        try:
            xml = verify_state(m, args.loopback)
            p.ok("Verification RPC OK")
            p.xml(xml, max_chars=4000)
        except RPCError as e:
            p.warn(f"VERIFY RPCError: {e}")

    # Close
    p.section("Finish")
    p.step("Done", ICON["done"], "Closing NETCONF session")
    m.close_session()
    p.ok("Session closed")
    print()

if __name__ == "__main__":
    main()
