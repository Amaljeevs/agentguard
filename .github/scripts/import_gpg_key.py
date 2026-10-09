"""Import a signing secret without printing its contents or GPG diagnostics."""

import os
import subprocess
import sys


def normalize_key(value: str) -> str:
    # Accept multiline GitHub secrets and exports pasted with escaped newlines.
    value = (value.replace("\\r\\n", "\n").replace("\\n", "\n")
             .replace("\r\n", "\n").strip())
    lines = value.splitlines()
    # Pasting an export can drop the required blank line between armor headers
    # and base64 data. Restore only that separator; leave key data unchanged.
    if lines and lines[0] == "-----BEGIN PGP PRIVATE KEY BLOCK-----":
        index = 1
        while index < len(lines) and ":" in lines[index]:
            index += 1
        if index < len(lines) and lines[index].strip():
            lines.insert(index, "")
    return "\n".join(lines) + "\n"


def import_error(diagnostics: bytes) -> str:
    # Return only fixed messages. Raw GPG stderr can echo private armor data.
    message = diagnostics.lower()
    if b"crc error" in message or b"invalid radix64" in message:
        return "GPG key data or checksum is damaged; re-export the private key."
    if b"invalid armor" in message:
        return "GPG rejected the armor formatting; preserve the export's headers and blank lines."
    if b"no valid openpgp data" in message:
        return "GPG found no valid OpenPGP key data in the supplied secret."
    if b"agent" in message:
        return "GPG could not complete secret-key import; check runner gpg-agent availability and key protection."
    return "GPG rejected the private key export; verify the complete export locally with gpg --import."


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
        print("::error::" + import_error(result.stderr))
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
