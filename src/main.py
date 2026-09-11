import argparse
import json

from classifier import classify_ioc, normalize_ioc
from scanner import IOCScanner


def main():

    parser = argparse.ArgumentParser(
        description="IOC Scanner - Local Threat Intelligence Scanner"
    )

    parser.add_argument(
        "ioc",
        help="IP, domain, URL, or file hash"
    )

    parser.add_argument(
        "--database",
        default="data/iocs.json",
        help="Path to IOC database"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON"
    )

    args = parser.parse_args()

    ioc = normalize_ioc(args.ioc)
    ioc_type = classify_ioc(ioc)

    if ioc_type == "unknown":
        print(f"[-] Unable to identify IOC: {ioc}")
        return

    try:
        scanner = IOCScanner(args.database)

        result = scanner.scan(
            ioc,
            ioc_type
        )

    except FileNotFoundError as error:
        print(f"[-] Error: {error}")
        return

    if args.json:
        print(json.dumps(result, indent=4))
        return

    print()
    print("=" * 45)
    print("              IOC SCANNER")
    print("=" * 45)

    print(f"IOC       : {result['ioc']}")
    print(f"Type      : {result['type'].upper()}")
    print(f"Status    : {result['status']}")
    print(f"Risk      : {result['risk']}")
    print(f"Timestamp : {result['timestamp']}")

    print("=" * 45)


if __name__ == "__main__":
    main()
