import argparse
from ..util import verify_by_pubkey

def handler(args):
    """Verify a signature on a file."""
    verify_by_pubkey(args.file, args.key, args.sig)

parser = argparse.ArgumentParser(
    description='Verify the signature on a file.',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument("--key", "-k", required=True, help="privkey")
parser.add_argument("--file", "-f", required=True, help="filename")
parser.add_argument("--sig", "-s", required=True, help="signature")
parser.set_defaults(handler=handler)