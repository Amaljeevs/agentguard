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
import xml.etree.ElementTree as ET

def get_project_version():
    """Extract release version from root pom.xml."""
    try:
        tree = ET.parse("pom.xml")
        root = tree.getroot()
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        v = root.find("m:version", ns)
        if v is not None and v.text:
            return v.text.strip()
    except Exception as e:
        print(f"Warning: Could not parse version from pom.xml: {e}")
    return "0.2.0"

def clean_staging_directory(staging_dir):
    """Purge any non-artifact or metadata files that cause Sonatype validation errors."""
    print("=== Cleaning up Maven metadata and rogue files ===")
    deleted_count = 0
    valid_extensions = (".jar", ".pom", ".asc", ".md5", ".sha1", ".sha256", ".sha512")
    
    # Bottom-up walk to allow directory removal
    for root, dirs, files in os.walk(staging_dir, topdown=False):
        for f in files:
            file_path = os.path.join(root, f)
            rel_path = os.path.relpath(file_path, staging_dir)
            parts = rel_path.split(os.sep)
            
            # A valid artifact must be inside: <group...>/<artifactId>/<version>/<file>
            # For io/github/amaljeevs/<artifactId>/<version>/<file>, there are 6 parts.
            should_remove = False
            if len(parts) < 6:
                print(f"Removing loose file outside version dir: {rel_path}")
                should_remove = True
            elif f.startswith(("maven-metadata", "_remote.repositories", ".")) or f.endswith((".zip", ".tmp")):
                print(f"Removing metadata/temp file: {rel_path}")
                should_remove = True
            elif not f.endswith(valid_extensions):
                print(f"Removing file with unsupported extension: {rel_path}")
                should_remove = True
            
            if should_remove:
                os.remove(file_path)
                deleted_count += 1
                
        # Remove empty directories
        for d in dirs:
            dir_path = os.path.join(root, d)
            if os.path.exists(dir_path) and not os.listdir(dir_path):
                try:
                    os.rmdir(dir_path)
                except OSError:
                    pass

    print(f"Removed {deleted_count} extraneous files.\n")

def validate_and_checksum(staging_dir):
    """Verify that every component folder has a .pom file and generate checksums."""
    print("=== Validating components and generating checksums ===")
    components = set()
    for root, dirs, files in os.walk(staging_dir):
        if files:
            rel_dir = os.path.relpath(root, staging_dir)
            components.add(rel_dir)
            
            # Check for POM file in this artifact directory
            has_pom = any(f.endswith(".pom") for f in files)
            if not has_pom:
                print(f"ERROR: Component directory '{rel_dir}' has content but NO .pom file: {files}")
                sys.exit(1)

            # Generate checksums for artifacts and signatures
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

    print(f"Validated {len(components)} components successfully:")
    for comp in sorted(components):
        print(f"  ✓ {comp}")
    print()

def package_bundle(staging_dir, bundle_path):
    """Create pristine bundle ZIP archive."""
    print(f"=== Packaging pristine bundle: {bundle_path} ===")
    total_files = 0
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(staging_dir):
            for f in sorted(files):
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, staging_dir)
                z.write(full_path, rel_path)
                total_files += 1
                print(f"  + {rel_path}")
    print(f"Packaged {total_files} files into {bundle_path}.\n")

def main():
    staging_dir = "target/central-staging"
    if not os.path.exists(staging_dir):
        print(f"Error: Staging directory '{staging_dir}' does not exist!")
        sys.exit(1)

    version = get_project_version()
    print(f"Publishing AgentGuard version: {version}")

    # 1. Clean staging directory of any files that trigger Sonatype errors
    clean_staging_directory(staging_dir)

    # 2. Validate every component directory has a .pom and create checksums
    validate_and_checksum(staging_dir)

    # 3. Create zip bundle
    bundle_path = "central-bundle.zip"
    package_bundle(staging_dir, bundle_path)

    # 4. Check credentials
    username = os.environ.get("MAVEN_CENTRAL_USERNAME", "").strip()
    token = os.environ.get("MAVEN_CENTRAL_TOKEN", "").strip()
    if not username or not token:
        print("Error: Missing MAVEN_CENTRAL_USERNAME or MAVEN_CENTRAL_TOKEN!")
        sys.exit(1)

    auth_str = f"{username}:{token}"
    auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")

    # 5. Upload to Sonatype Central Portal API
    print("=== Uploading bundle to Sonatype Central Portal API ===")
    boundary = "----AgentGuardFormBoundary" + str(int(time.time()))
    upload_url = f"https://central.sonatype.com/api/v1/publisher/upload?publishingType=AUTOMATIC&name=AgentGuard-{version}"

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

    # 6. Monitor deployment status
    print(f"\n=== Monitoring deployment {deployment_id} ===")
    status_url = f"https://central.sonatype.com/api/v1/publisher/status?id={deployment_id}"
    for attempt in range(1, 61):
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
                print(f"[{attempt}/60] State: {state}")
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
