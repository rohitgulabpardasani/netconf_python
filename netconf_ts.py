#!/usr/bin/env python3
# netconf_candidate_validate_commit_save.py

import argparse
import sys
from typing import Optional
from xml.etree import ElementTree as ET
from ncclient import manager
from ncclient.operations import RPCError
from ncclient.xml_ import to_ele

STUDENT_FULL_RPC_XML = r"""
<!-- PASTE FULL <rpc> XML FROM YANG SUITE HERE -->
"""

NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"

def _die(msg: str, code: int = 1):
    print(f"[FAIL] {msg}")
    sys.exit(code)

def extract_config_from_rpc(rpc_xml: str) -> str:
    rpc_xml = rpc_xml.strip()
    if not rpc_xml or rpc_xml.startswith("<!-- PASTE"):
        _die("NO XML found")
    try:
        root = ET.fromstring(rpc_xml)
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML: {e}")

    def localname(tag: str) -> str:
        return tag.split('}', 1)[-1] if tag.startswith('{') else tag

    def namespace(tag: str) -> Optional[str]:
        return tag[1:].split('}')[0] if tag.startswith('{') else None

    cfg = None
    for node in root.iter():
        if localname(node.tag) == 'config':
            cfg = node
            break
    if cfg is None:
        raise ValueError("Could not find <config> element inside the RPC.")

    cfg_ns = namespace(cfg.tag)
    if cfg_ns is None:
        children_xml = ''.join(ET.tostring(child, encoding='unicode') for child in list(cfg))
        return f"<config xmlns=\"{NETCONF_NS}\">{children_xml}</config>"
    return ET.tostring(cfg, encoding="unicode")

def main():
    parser = argparse.ArgumentParser(description="Apply student RPC to candidate, validate, commit, and save")
    parser.add_argument("--host", default="192.168.122.2")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--user", default="ineuser")
    parser.add_argument("--password", default="ine123")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        import logging
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    try:
        student_config_xml = extract_config_from_rpc(STUDENT_FULL_RPC_XML)
    except ValueError as e:
        _die(str(e))

    print("[INFO] Using <config> extracted from student RPC export")

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
        if not any(":candidate" in c for c in caps):
            _die(":candidate datastore not supported by device.")
        has_startup = any(":startup" in c for c in caps)

        print("[STEP] Lock candidate")
        m.lock(target="candidate")
        try:
            print("[STEP] edit-config target=candidate")
            m.edit_config(target="candidate", config=student_config_xml, default_operation="merge")

            print("[STEP] validate source=candidate")
            m.validate(source="candidate")

            print("[STEP] commit")
            m.commit()
            print("[OK] Commit successful")

            if has_startup:
                print("[STEP] copy-config running -> startup")
                m.copy_config(target="startup", source="running")
                print("[OK] Saved to startup")
            else:
                print("[STEP] startup not supported; attempting Cisco save-config RPC")
                try:
                    save_ele = to_ele('<cisco-ia:save-config xmlns:cisco-ia="http://cisco.com/yang/cisco-ia"/>')
                    m.dispatch(save_ele)
                    print("[OK] Cisco save-config RPC dispatched")
                except Exception as e:
                    print(f"[WARN] save-config RPC failed: {e}")
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
