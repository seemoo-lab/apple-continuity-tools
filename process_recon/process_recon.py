#!/usr/bin/env python3

import argparse
import json
import subprocess
import threading

processes = {}
subsystems = {}
categories = {}


def process_log_entry(obj, verbose=False):
    process = obj["processImagePath"]
    subsystem = obj["subsystem"]
    category = obj["category"]
    message = obj["eventMessage"]
    if process:
        processes[process] = processes.get(process, 0) + 1
    if subsystem:
        subsystems[subsystem] = subsystems.get(subsystem, 0) + 1
    if category:
        categories[category] = categories.get(category, 0) + 1
    if verbose:
        print(f"{process} ({subsystem}) [{category}]: {message}")


def construct_predicate(keywords: str):
    # Valid predicates via `log help predicates`
    CONTAINS = "CONTAINS[c]"  # [c] for case-insensitive matching
    predicates = None
    for keyword in keywords:
        predicate = f"composedMessage {CONTAINS} '{keyword}'"
        if predicates is None:
            predicates = predicate
        else:
            predicates = f"{predicates} OR {predicate}"
    return predicates


def gather_logs(keywords: [str], verbose=False):
    log_command = [
        "log",
        "stream",
        "--style",
        "json",
        "--level",
        "debug",
        "--predicate",
        construct_predicate(keywords),
    ]

    popen = subprocess.Popen(log_command, stdout=subprocess.PIPE)

    try:
        print(f"Scanning logs for {keywords}. Press Ctrl+C to stop ...")
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        f = popen.stdout
        f.readline()  # first line is garbage
        for obj in json.load(f):
            process_log_entry(obj, verbose=verbose)


def main():
    global verbose
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "keywords",
        type=str,
        nargs="+",
        help="One or more keywords to scan for",
    )
    parser.add_argument(
        "-v", "--verbose", help="Print individual log entries", action="store_true"
    )
    args = parser.parse_args()

    gather_logs(args.keywords, args.verbose)

    def print_summary(alist, name=None):
        if name:
            print(f"{name} ({len(alist)}):")
        alist_sorted = dict(sorted(alist.items(), key=lambda x: x[1], reverse=True))
        for k, v in alist_sorted.items():
            print(f"\t{k} ({v})")

    print("\n\nDiscovery summary:")
    print_summary(processes, name="Processes")
    print_summary(categories, name="Categories")
    print_summary(subsystems, name="Subsystems")

    if not processes and not categories and not subsystems:
        print("\tNo results found. Keep the script running a bit longer.")


if __name__ == "__main__":
    main()
