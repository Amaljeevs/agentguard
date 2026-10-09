"""Import a signing secret without printing its contents or GPG diagnostics."""

import os
import subprocess
import sys


def normalize_key(value: str) -> str:
    # Accept multiline GitHub secrets and exports pasted with escaped newlines.
    return (value.replace("\\r\\n", "\n").replace("\\n", "\n")
            .replace("\r\n", "\n").strip() + "\n")


def main() -> int:
    key = normalize_key(os.environ.get("GPG_KEY", ""))
    if not key.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----\n") or not key.rstrip().endswith(
        "-----END PGP PRIVATE KEY BLOCK-----"
    ):
        print("::error::GPG_PRIVATE_KEY must contain an ASCII-armored private key export.")
        return 1

    result = subprocess.run(
        ["gpg", "--batch", "--import"], input=key.encode("utf-8"), capture_output=True
    )
    if result.returncode:
        print("::error::GPG import failed. Replace GPG_PRIVATE_KEY with a complete, valid private key export.")
        return 1

    keys = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-secret-keys"], capture_output=True
    )
    if keys.returncode or not any(line.startswith(b"sec:") for line in keys.stdout.splitlines()):
        print("::error::No secret key is available after import.")
        return 1
    print("Signing key imported successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
