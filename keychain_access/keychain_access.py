#!/usr/bin/env python3

import argparse
import json
import os
import sys

import frida

keychainItems = list()


def on_message(message, data):
    global keychainItems
    print(f"{message}")
    msg = message["payload"]
    keychainItems.append(msg)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("process", type=str, help="Process name or ID to hook")
    parser.add_argument(
        "-o", "--output_file", help="Output file", default="keychain_access.json"
    )
    args = parser.parse_args()

    if args.process.isdigit():
        process_id = int(args.process)
        session = frida.attach(process_id)
    else:
        session = frida.attach(args.process)

    script_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "frida_scripts/hook_SecItemCopyMatching.js",
    )
    with open(script_file, "r") as hook_file:
        hook = hook_file.read()

    script = session.create_script(hook)
    script.on("message", on_message)
    script.load()
    print("[Press Ctrl+D to stop and save keychain items]")
    sys.stdin.read()
    print(keychainItems)
    with open(args.output_file, "w") as keychain_file:
        json.dump(keychainItems, keychain_file)
    session.detach()


if __name__ == "__main__":
    main()
