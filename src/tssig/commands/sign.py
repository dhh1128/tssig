import argparse
from ..util import sign_to_file

def handler(args):
    """Sign a file with an identifier."""
    sign_to_file(args.file, args.key)

parser = argparse.ArgumentParser(
    description='Sign a file.',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter
)
parser.add_argument("--key", "-k", required=True, help="privkey")
parser.add_argument("--file", "-f", required=True, help="filename")
parser.set_defaults(handler=handler)