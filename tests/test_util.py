import os
import pytest
import subprocess
import tempfile

from tssig import sign, verify_by_pubkey, verify_by_identifier

@pytest.fixture
def ed25519_key():
    with tempfile.TemporaryDirectory() as temp_dir:
        key_path = temp_dir + '/key'
        subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', key_path, '-N', ''], check=True)
        yield key_path

def test_sign_and_verify(ed25519_key):
    #print(ed25519_key)
    fname = ed25519_key + ".testdata"
    with open(fname, "wt") as f:
        f.write("test data" + os.urandom(64).hex())
    unsigned = fname + '.unsigned'
    with open(unsigned, "wt") as f:
        f.write("test data" + os.urandom(64).hex())
    signature = sign(fname, ed25519_key)
    sig_fname = fname + ".sig"
    with open(sig_fname, "wt") as f:
        f.write(signature)
    #print(signature)
    assert signature
    assert verify_by_pubkey(fname, ed25519_key + '.pub', sig_fname)
    with pytest.raises(Exception):
        verify_by_pubkey(unsigned, ed25519_key + '.pub', sig_fname)
