#!/usr/bin/env python3
# netconf_candidate_validate_commit_save.py
#
# Minimal teaching script that:
#   1) Accepts a full <rpc> ... </rpc> pasted from YANG Suite (student block)
#   2) Extracts the <config> subtree from that RPC
#   3) Applies it to the *candidate* datastore
#   4) Validates candidate
#   5) Commits to running
#   6) Saves configuration (startup or Cisco save-config if available)
#
# If the device doesn't advertise :candidate, the script exits with an error.
# If :startup is missing, it tries Cisco's cisco-ia:save-config RPC.
#
# ---------------------------------------------------------------
# HOW STUDENTS USE THIS
# 1) In YANG Suite, build your desired change and export the **full NETCONF RPC**
#    (it will include <rpc> <edit-config> <target> <running/> ... <config> ... )
# 2) Paste that entire XML between the triple quotes in STUDENT_FULL_RPC_XML below.
# 3) Run the script. It will ignore the student's <target> and push to *candidate*,
#    then validate, commit to running, and save.
# ---------------------------------------------------------------

import argparse
import sys
from xml.etree import ElementTree as ET
from ncclient import manager
from ncclient.operations import RPCError

# -------------------- STUDENT FULL <rpc> XML (PASTE HERE) --------------------
STUDENT_FULL_RPC_XML = r"""
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101">
  <edit-config>
    <target>
      <running/>
    </target>
    <config>
      <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
        <hostname>NETCONF-EDGE</hostname>
      </native>
    </config>
  </edit-config>
</rpc>
"""
# ------------------ END STUDENT FULL <rpc> XML (PASTE HERE) ------------------

NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
NSMAP = {"nc": NETCONF_NS}


def _die(msg: str, code: int = 1):
    print(f"[FAIL] {msg}")
    sys.exit(code)


def extract_config_from_rpc(rpc_xml: str) -> str:
    """Return the serialized <config> element (including its tag) from a full <rpc>.
    Raises ValueError if not found.
    """
    try:
        root = ET.fromstring(rpc_xml.strip())
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {e}")

    # Find the <config> element under any edit-config
    cfg = root.find(f".//{{{NETCONF_NS}}}config")
    if cfg is None:
        # If student's export used a default namespace on rpc, ElementTree may not bind prefixes.
        # Try a naive search by tag name 'config'.
        for child in root.iter():
            if child.tag.endswith('config'):
                cfg = child
                break
    if cfg is None:
        raise ValueError("Could not find <config> element inside the RPC. Make sure you pasted the full YANG Suite RPC.")

    # Re-serialize <config> including namespace declarations
    return ET.tostring(cfg, encoding="unicode")


def main():
    parser = argparse.ArgumentParser(description="Apply student RPC to candidate, validate, commit, and save")
    parser.add_argument("--host", default="192.168.122.2", help="Router IP/hostname (default: 192.168.122.2)")
    parser.add_argument("--port", type=int, default=830, help="NETCONF port (default: 830)")
    parser.add_argument("--user", default="ineuser", help="Username (default: ineuser)")
    parser.add_argument("--password", default="ine123", help="Password (default: ine123)")
    parser.add_argument("--debug", action="store_true", help="Enable ncclient/paramiko DEBUG logging")
    args = parser.parse_args()

    if args.debug:
        import logging
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    # 1) Extract <config> from student's <rpc>
    try:
        student_config_xml = extract_config_from_rpc(STUDENT_FULL_RPC_XML)
    except ValueError as e:
        _die(str(e))

    print("[INFO] Using <config> extracted from student RPC export")

    # 2) Connect
    try:
        m = manager.connect(
            host=args.host,
            port=args.port,
            username=args.user,
            password=args.password,
            hostkey_verify=False,
            allow_agent=False,
            look_for_keys=False,
            timeout=60,
        )
    except Exception as e:
        _die(f"NETCONF SSH connect failed: {type(e).__name__}: {e}")

    try:
        caps = list(m.server_capabilities)
        has_candidate = any(":candidate" in c for c in caps)
        has_startup = any(":startup" in c for c in caps)

        if not has_candidate:
            _die(":candidate datastore not supported by device. This lab requires :candidate.")

        print(f"[INFO] Capabilities ok (candidate={has_candidate}, startup={has_startup})")

        # 3) Lock candidate
        print("[STEP] Lock candidate")
        m.lock(target="candidate")

        try:
            # 4) Edit candidate with student's config
            print("[STEP] edit-config target=candidate")
            m.edit_config(target="candidate", config=student_config_xml, default_operation="merge")

            # 5) Validate candidate
            print("[STEP] validate source=candidate")
            m.validate(source="candidate")

            # 6) Commit to running
            print("[STEP] commit")
            m.commit()
            print("[OK] Commit successful")

            # 7) Save configuration
            if has_startup:
                print("[STEP] copy-config running -> startup")
                m.copy_config(target="startup", source="running")
                print("[OK] Saved to startup")
            else:
                # Try Cisco's save-config RPC as a best-effort
                print("[STEP] startup not supported; attempting Cisco cisco-ia:save-config RPC")
                save_rpc = (
                    f"<rpc xmlns=\"{NETCONF_NS}\" message-id=\"save1\">"
                    "<cisco-ia:save-config xmlns:cisco-ia=\"http://cisco.com/yang/cisco-ia\"/>"
                    "</rpc>"
                )
                try:
                    m.dispatch(save_rpc)
                    print("[OK] Cisco save-config RPC dispatched")
                except Exception as e:
                    print(f"[WARN] save-config RPC failed or unsupported: {e}")

        finally:
            print("[STEP] Unlock candidate")
            try:
                m.unlock(target="candidate")
                print("[OK] Candidate unlocked")
            except Exception as e:
                print(f"[WARN] Unlock failed: {e}")

    except RPCError as e:
        _die(f"NETCONF RPCError: {e}")
    except Exception as e:
        _die(f"Unexpected error: {type(e).__name__}: {e}")
    finally:
        try:
            m.close_session()
            print("[DONE] Session closed")
        except Exception:
            pass


if __name__ == "__main__":
    main()
