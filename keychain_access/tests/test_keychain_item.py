#!/usr/bin/env python3

import argparse
import binascii
import json
import sys


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--secret", help="Test secret")
    parser.add_argument("-l", "--label", help="Test service label")
    parser.add_argument("-f", "--file", help="Export file")
    args = parser.parse_args(args)

    with open(args.file, "r") as file:
        export = json.load(file)

    if len(export) == 0:
        print("No secrets in export file")
        return 1

    label = export[0]["query"]["labl"]
    if label != args.label:
        print(f"Label not matching: was {label}, expected {args.label}")
        return 1

    result = export[0]["result"]
    if result is None:
        print(f"No secret found")
        return 1
    result_decoded = binascii.unhexlify(result[2:]).decode()  # remove '0x' prefix
    if result_decoded != args.secret:
        print(f"Secret not matching: was {result_decoded}, expected {args.secret}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
