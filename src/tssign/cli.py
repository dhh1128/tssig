import sys
import argparse
from multicommand import MultiCommand, command

from .util import sign, verify_by_identifier, verify_by_pubkey

cli = MultiCommand(prog="seqsign", description="Work with sequenced signatures.")

@command(cli, name="sign")
def sign_command(args):
    """Sign a file with an identifier."""
    if not args.i or not args.f:
        print("Error: Missing required arguments for signing.", file=sys.stderr)
        sys.exit(1)
    sign(args.i, args.f)

@command(cli, name="verify")
def verify_command(args):
    """Verify a signed file."""
    if not args.i or not args.s or not args.f:
        print("Error: Missing required arguments for verification.", file=sys.stderr)
        sys.exit(1)
    verify_by_identifier(args.i, args.s, args.f)

def main():
    parser = argparse.ArgumentParser(description="SeqSign CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a file")
    sign_parser.add_argument("-i", required=True, help="Identifier")
    sign_parser.add_argument("-f", required=True, help="Filename")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a signed file")
    verify_parser.add_argument("-i", required=True, help="Identifier")
    verify_parser.add_argument("-s", required=True, help="Signature")
    verify_parser.add_argument("-f", required=True, help="Filename")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli.main(args)

if __name__ == "__main__":
    main()
