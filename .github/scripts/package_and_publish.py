import os
import sys
import glob
import time
import base64
import hashlib
import zipfile
import urllib.request
import urllib.parse
import json

def main():
    staging_dir = "target/central-staging"
    if not os.path.exists(staging_dir):
        print(f"Error: Staging directory {staging_dir} does not exist!")
        sys.exit(1)

    print("=== Cleaning up Maven metadata and repo artifacts ===")
    deleted_count = 0
    for root, dirs, files in os.walk(staging_dir):
        for f in files:
            if f.startswith("maven-metadata") or f.startswith("_remote.repositories") or f.endswith(".zip"):
                file_path = os.path.join(root, f)
                print(f"Removing invalid bundle file: {file_path}")
                os.remove(file_path)
                deleted_count += 1
    print(f"Removed {deleted_count} extraneous files.")

    print("\n=== Verifying and generating checksums ===")
    for root, dirs, files in os.walk(staging_dir):
        for f in files:
            if f.endswith((".jar", ".pom", ".asc")):
                filepath = os.path.join(root, f)
                with open(filepath, "rb") as fp:
                    data = fp.read()
                for ext, algo in [
                    (".md5", hashlib.md5),
                    (".sha1", hashlib.sha1),
                    (".sha256", hashlib.sha256),
                    (".sha512", hashlib.sha512),
                ]:
                    chk_path = filepath + ext
                    if not os.path.exists(chk_path):
                        with open(chk_path, "w") as out:
                            out.write(algo(data).hexdigest())

    bundle_path = "central-bundle.zip"
    print(f"\n=== Packaging pristine bundle: {bundle_path} ===")
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(staging_dir):
            for f in files:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, staging_dir)
                z.write(full_path, rel_path)
                print(f"  + {rel_path}")

    username = os.environ.get("MAVEN_CENTRAL_USERNAME", "").strip()
    token = os.environ.get("MAVEN_CENTRAL_TOKEN", "").strip()
    if not username or not token:
        print("Error: Missing MAVEN_CENTRAL_USERNAME or MAVEN_CENTRAL_TOKEN!")
        sys.exit(1)

    auth_str = f"{username}:{token}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")

    print("\n=== Uploading bundle to Sonatype Central Portal API ===")
    boundary = "----AgentGuardFormBoundary" + str(int(time.time()))
    upload_url = "https://central.sonatype.com/api/v1/publisher/upload?publishingType=AUTOMATIC&name=AgentGuard-0.2.0"

    with open(bundle_path, "rb") as f:
        file_bytes = f.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="bundle"; filename="{bundle_path}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    req = urllib.request.Request(
        upload_url,
        data=body,
        headers={
            "Authorization": f"Bearer {auth_b64}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req) as resp:
            resp_data = resp.read().decode("utf-8")
            deployment_id = resp_data.strip().strip('"')
            print(f"Bundle uploaded successfully! Deployment ID: {deployment_id}")
    except Exception as e:
        print(f"Upload failed: {e}")
        if hasattr(e, 'read'):
            print(e.read().decode("utf-8", errors="replace"))
        sys.exit(1)

    print(f"\n=== Monitoring deployment {deployment_id} ===")
    status_url = f"https://central.sonatype.com/api/v1/publisher/status?id={deployment_id}"
    for attempt in range(1, 40):
        time.sleep(5)
        status_req = urllib.request.Request(
            status_url,
            headers={"Authorization": f"Bearer {auth_b64}"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(status_req) as s_resp:
                s_data = json.loads(s_resp.read().decode("utf-8"))
                state = s_data.get("deploymentState", "UNKNOWN")
                print(f"[{attempt}/40] State: {state}")
                if state in ("PUBLISHED", "VALIDATED"):
                    print(f"\nSUCCESS! Deployment {deployment_id} is {state} on Maven Central!")
                    sys.exit(0)
                elif state == "FAILED":
                    print(f"\nDEPLOYMENT FAILED:")
                    print(json.dumps(s_data, indent=2))
                    sys.exit(1)
        except Exception as se:
            print(f"Status check notice: {se}")

    print("Timed out waiting for validation; check https://central.sonatype.com/publishing")

if __name__ == "__main__":
    main()
