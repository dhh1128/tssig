# Implements the technique documented at https://www.agwa.name/blog/post/ssh_signatures.

import io
import os
import re
import subprocess
import tempfile

DEFAULT_NAMESPACE = "daniel.hardman+tssig@gmail.com"
SSH_PUBKEY_PAT = re.compile(r'^(ssh-(?:rsa|dss|ed25519|ecdsa)(?:-[a-z0-9]+)?) ([A-Za-z0-9+/=]+)(?: +([^ ]+))?$')
SSH_SIG_PREFIX = "-----BEGIN SSH SIGNATURE-----"

def sign(fname: str, path_to_privkey: str, namespace: str=DEFAULT_NAMESPACE) -> str:
    """
    Use the specified private SSH key to generate a signature over the
    contents of the specified file, using the specified namespace.
    Return the signature as a string.
    """
    with open(fname, "rb") as f:
        # Run ssh-keygen with subprocess
        process = subprocess.Popen(
            ["ssh-keygen", "-Y", "sign", "-n", namespace, "-f", path_to_privkey],
            stdin=subprocess.PIPE,  # Pass data through stdin
            stdout=subprocess.PIPE,  # Capture stdout
            stderr=subprocess.PIPE,  # Capture stderr (optional for debugging)
        )
        signed_output, error_output = process.communicate(input=f.read())
        if process.returncode != 0:
            raise Exception(error_output.decode())
        return signed_output.decode()
    
def sign_to_file(fname: str, path_to_privkey: str, dest: str=None, namespace: str=DEFAULT_NAMESPACE):
    """
    Use the specified private SSH key to generate a signature over the
    contents of the specified file, using the specified namespace.
    Write the signature to a file with the same name as the input file,
    but with a ".sig" extension.
    """
    signature = sign(fname, path_to_privkey, namespace)
    if not dest:
        dest = fname + ".sig"
    with open(dest, "wt") as f:
        f.write(signature)

def is_file_like(obj):
    return isinstance(obj, io.IOBase)
    
def verify_by_pubkey(fname_or_fileobj, pubkey_fname_or_val: str, sig_fname_or_val: str, 
                     namespace: str=DEFAULT_NAMESPACE) -> bool:
    """
    Use the specified SSH pubkey (as a string) or path to a pubkey file (*.pub) to
    verify a signature over a given file, using the specified namespace. Return 
    True if all is well. Otherwise, raise an Exception describing the error.
    """
    if not is_file_like(fname_or_fileobj):
        if not os.path.isfile(fname_or_fileobj):
            raise Exception(f"File '{fname_or_fileobj}' does not exist.")
    # See whether we got an actual pubkey, or just the path to a pubkey file.
    m = SSH_PUBKEY_PAT.match(pubkey_fname_or_val)
    if not m:
        # If it's a path, read the key from the file.
        with open(pubkey_fname_or_val, "rt") as f:
            txt = f.read().strip()
            m = SSH_PUBKEY_PAT.match(txt)
        if not m:
            raise Exception(f"Pubkey '{pubkey_fname_or_val}' neither contains an SSH key nor a path to a pubkey file.")
    # Now that we have the actual value of a key, pick an identifier for it. It might
    # have an identifier in the comment of its pubkey file, or we might have to make one
    # up. Either way, we we use what we now know to write an "allowed signers" file in
    # the format that ssh-keygen expects. This is never the format of the data we received;
    # if the caller had that kind of file, they should have directly called verify_by_identifier.
    identifier = m.group(3)
    if not identifier: identifier = "x"
    with tempfile.NamedTemporaryFile(mode="w+t") as temp_file:
        temp_file.write(f"{identifier} {m.group(1)} {m.group(2)}")
        temp_file.flush()
        return verify_by_identifier(fname_or_fileobj, identifier, temp_file.name, sig_fname_or_val, namespace)

def verify_by_identifier(fname_or_fileobj, identifier: str, identifier_to_pubkeys_file: str, 
                         sig_fname_or_val: str, namespace: str=DEFAULT_NAMESPACE) -> bool:
    """
    Use the specified identifier and an "allowed signers" file (which may list several
    keys used by the same user) to verify a signature by a user over a given file,
    using the specified namespace. Return True if all is well. Otherwise, raise an
    Exception describing the error.
    """
    f = fname_or_fileobj if is_file_like(fname_or_fileobj) else open(fname_or_fileobj, "rb")
    with f:
        # ssh-keygen requires the signature to exist in an external file. If we got an
        # actual signature value, write it to a temp file that we will later delete.
        if sig_fname_or_val.startswith(SSH_SIG_PREFIX):
            fd, sig_fname = tempfile.mkstemp()
            fd.write(sig_fname_or_val)
            fd.close()
            cleanup = True
        else:
            sig_fname = sig_fname_or_val
            cleanup = False
        try:
            # Run ssh-keygen with subprocess
            process = subprocess.Popen(
                ["ssh-keygen", "-Y", "verify", "-f", identifier_to_pubkeys_file, 
                "-I", identifier, "-n", namespace, "-s", sig_fname_or_val],
                stdin=subprocess.PIPE,  # Pass data through stdin
                stdout=subprocess.PIPE,  # Capture stdout
                stderr=subprocess.PIPE,  # Capture stderr (optional for debugging)
            )
            _, error_output = process.communicate(input=f.read())
        finally:
            if cleanup: os.remove(sig_fname)
        if process.returncode != 0:
            raise Exception(error_output.decode())
        return True