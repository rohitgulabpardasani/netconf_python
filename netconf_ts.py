#!/usr/bin/env python3
# netconf_candidate_validate_commit_save_fancy.py
#
# Fancy teaching script that:
#   1) Lets students paste a full <rpc>...</rpc> from YANG Suite (or pass --rpc-file)
#   2) Extracts the inner <config> block
#   3) Applies to candidate → validate → commit → save (startup or Cisco save-config)
#   4) Pretty, numbered steps with optional color and XML pretty-printing
#   5) Clear error handling (prints "NO XML found" when student block is empty)
#
# Python 3.8+ compatible.

import argparse
import os
import sys
import textwrap
from typing import Optional
from xml.etree import ElementTree as ET

from ncclient import manager
from ncclient.operations import RPCError
from ncclient.xml_ import to_ele

# -------------------- STUDENT FULL <rpc> XML (PASTE HERE) --------------------
STUDENT_FULL_RPC_XML = r"""
<!-- PASTE FULL <rpc> XML FROM YANG SUITE HERE -->
"""
# ------------------ END STUDENT FULL <rpc> XML (PASTE HERE) ------------------

NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"

# --------------------------- Pretty printing ---------------------------------

def _supports_color() -> bool:
    return sys.stderr.isatty()

class C:
    if _supports_color():
        RESET = "\033[0m"; BOLD = "\033[1m"
        RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"; GRAY = "\033[90m"
    else:
        RESET = BOLD = RED = GREEN = YELLOW = BLUE = GRAY = ""

ICON = {
    "sec": "[SEC]", "plan": "[PLAN]", "ok": "[OK]", "warn": "[WARN]", "fail": "[FAIL]",
    "net": "[NET]", "ssh": "[SSH]", "caps": "[CAP]", "lock": "[LOCK]", "edit": "[EDIT]",
    "val": "[VAL]", "commit": "[COMMIT]", "save": "[SAVE]", "unlock": "[UNLOCK]", "done": "[DONE]",
}

class Printer:
    def __init__(self, use_color: bool = True, show_xml: str = "on"):
        self.n = 0
        self.use_color = use_color and _supports_color()
        self.show_xml = (show_xml == "on")

    def c(self, s: str, color: str) -> str:
        return f"{color}{s}{C.RESET}" if self.use_color else s

    def section(self, title: str):
        bar = "-" * 84
        print(self.c(bar, C.GRAY))
        print(f"{ICON['sec']}  {self.c(title, C.BOLD)}")
        print(self.c(bar, C.GRAY))

    def step(self, label: str, icon: str, msg: str):
        self.n += 1
        left = self.c(f"[Step {self.n:02d}]", C.BLUE)
        print(f"{left} {icon} {self.c(label, C.BOLD)} - {msg}")

    def ok(self, msg: str = "OK"): print(self.c(f"  {ICON['ok']} {msg}", C.GREEN))
    def warn(self, msg: str):     print(self.c(f"  {ICON['warn']} {msg}", C.YELLOW))
    def fail(self, msg: str):     print(self.c(f"  {ICON['fail']} {msg}", C.RED))

    def xml(self, xml_text: str, header: str = "XML", max_chars: int = 6000):
        if not self.show_xml:
            self.warn("(XML suppressed; run with --xml on)")
            return
        pretty = _pretty_xml(xml_text)
        if len(pretty) > max_chars:
            pretty = pretty[:max_chars] + "\n... [truncated]"
        print(self.c(f"  -- {header} (pretty) -----------------------------------------------", C.GRAY))
        for ln in pretty.splitlines():
            print(self.c("  | ", C.GRAY) + ln)
        print(self.c("  --------------------------------------------------------------------", C.GRAY))


def _pretty_xml(xml_text: str) -> str:
    try:
        from xml.dom import minidom
        xml_str = xml_text.lstrip()
        dom = minidom.parseString(xml_str.encode("utf-8") if isinstance(xml_str, str) else xml_str)
        out = dom.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
        return "\n".join([l for l in out.splitlines() if l.strip()])
    except Exception:
        return xml_text

# ---------------------------- Helpers ----------------------------------------

def _die(p: Printer, msg: str, code: int = 1):
    p.fail(msg)
    sys.exit(code)

def _load_student_rpc_from_sources(p: Printer, cli_rpc_file: Optional[str]) -> str:
    """Load student RPC from (priority): CLI file, env XML_STUDENT_RPC, paste block.
    Returns the full <rpc> XML string.
    """
    if cli_rpc_file:
        path = os.path.expanduser(cli_rpc_file)
        if not os.path.exists(path):
            _die(p, f"RPC file not found: {path}")
        return open(path, "r", encoding="utf-8").read()

    env = os.environ.get("XML_STUDENT_RPC", "").strip()
    if env:
        return env

    pasted = STUDENT_FULL_RPC_XML.strip()
    if not pasted or pasted.startswith("<!-- PASTE"):
        _die(p, "NO XML found")
    return pasted

# Precise <config> extraction with namespace-safe handling

def extract_config_from_rpc(p: Printer, rpc_xml: str) -> str:
    try:
        root = ET.fromstring(rpc_xml)
    except ET.ParseError as e:
        _die(p, f"Invalid XML: {e}")

    def localname(tag: str) -> str:
        return tag.split('}', 1)[-1] if tag.startswith('{') else tag

    def namespace(tag: str) -> Optional[str]:
        return tag[1:].split('}')[0] if tag.startswith('{') else None

    cfg = None
    for node in root.iter():
        if localname(node.tag) == 'config':
            cfg = node; break
    if cfg is None:
        _die(p, "Could not find <config> element inside the RPC. Ensure you pasted the full <rpc> export.")

    cfg_ns = namespace(cfg.tag)
    if cfg_ns is None:
        # wrap children into correctly-namespaced <config>
        children_xml = ''.join(ET.tostring(child, encoding='unicode') for child in list(cfg))
        return f"<config xmlns=\"{NETCONF_NS}\">{children_xml}</config>"
    return ET.tostring(cfg, encoding="unicode")

# -------------------------------- Main ---------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Candidate → validate → commit → save with student RPC",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    ap.add_argument("--host", default="192.168.122.2", help="NETCONF host (default: 192.168.122.2)")
    ap.add_argument("--port", type=int, default=830, help="NETCONF port (default: 830)")
    ap.add_argument("--user", default="ineuser", help="Username (default: ineuser)")
    ap.add_argument("--password", default="ine123", help="Password (default: ine123)")
    ap.add_argument("--rpc-file", help="Load full <rpc> XML from file (overrides paste block)")
    ap.add_argument("--xml", choices=["on","off"], default="on", help="Print XML (default: on)")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    ap.add_argument("--yes", action="store_true", help="Skip confirm prompt for apply path")
    ap.add_argument("--debug", action="store_true", help="Enable ncclient/paramiko DEBUG logs")

    args = ap.parse_args()
    if args.debug:
        import logging
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    p = Printer(use_color=not args.no_color, show_xml=args.xml)

    # Header
    p.section("IOS-XE NETCONF: Candidate → Validate → Commit → Save")
    p.step("Plan", ICON['plan'], "Inputs")
    p.ok(f"Host={args.host}  Port={args.port}  User={args.user}")
    p.ok(f"XML printing={args.xml}  Color={'off' if args.no_color else 'on'}")

    # Load RPC
    p.step("Load", ICON['plan'], "Get student RPC XML")
    rpc_xml = _load_student_rpc_from_sources(p, args.rpc_file)
    p.ok("Student RPC loaded")

    # Extract config
    p.step("Parse", ICON['plan'], "Extract <config> from RPC")
    config_xml = extract_config_from_rpc(p, rpc_xml)
    p.ok("<config> extracted")
    p.xml(config_xml, header="Outgoing <config>")

    if not args.yes:
        p.warn("Press Enter to proceed (Ctrl+C to abort)…")
        try: input()
        except KeyboardInterrupt:
            _die(p, "Aborted by user")

    # Connect
    p.section("Connect & Capabilities")
    p.step("Connect", ICON['ssh'], "NETCONF over SSH")
    try:
        m = manager.connect(
            host=args.host, port=args.port, username=args.user, password=args.password,
            hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=60,
        )
        p.ok("Connected")
    except Exception as e:
        _die(p, f"NETCONF SSH connect failed: {type(e).__name__}: {e}")

    try:
        caps = list(m.server_capabilities)
        has_candidate = any(":candidate" in c for c in caps)
        has_startup = any(":startup" in c for c in caps)
        p.step("Caps", ICON['caps'], f"candidate={has_candidate} startup={has_startup}")
        if not has_candidate:
            _die(p, ":candidate datastore not supported by device.")

        # Lock
        p.section("Change Flow")
        p.step("Lock", ICON['lock'], "Lock candidate")
        m.lock(target="candidate"); p.ok("Locked")
        try:
            # Edit candidate
            p.step("Edit", ICON['edit'], "edit-config target=candidate (merge)")
            m.edit_config(target="candidate", config=config_xml, default_operation="merge")
            p.ok("edit-config RPC OK")

            # Validate
            p.step("Validate", ICON['val'], "validate source=candidate")
            m.validate(source="candidate"); p.ok("Validation passed")

            # Commit
            p.step("Commit", ICON['commit'], "commit candidate → running")
            m.commit(); p.ok("Commit OK")

            # Save
            if has_startup:
                p.step("Save", ICON['save'], "copy-config running → startup")
                m.copy_config(target="startup", source="running"); p.ok("Saved to startup")
            else:
                p.step("Save", ICON['save'], "Cisco cisco-ia:save-config (best effort)")
                try:
                    save_ele = to_ele('<cisco-ia:save-config xmlns:cisco-ia="http://cisco.com/yang/cisco-ia"/>')
                    m.dispatch(save_ele); p.ok("save-config RPC dispatched")
                except Exception as e:
                    p.warn(f"save-config RPC failed or unsupported: {e}")

        finally:
            p.step("Unlock", ICON['unlock'], "Unlock candidate")
            try:
                m.unlock(target="candidate"); p.ok("Unlocked")
            except Exception as e:
                p.warn(f"Unlock failed: {e}")

    except RPCError as e:
        _die(p, f"NETCONF RPCError: {e}")
    except Exception as e:
        _die(p, f"Unexpected error: {type(e).__name__}: {e}")
    finally:
        try:
            p.section("Finish")
            p.step("Done", ICON['done'], "Close session")
            m.close_session(); p.ok("Session closed")
        except Exception:
            pass

if __name__ == "__main__":
    main()
