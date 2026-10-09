import os
import tempfile
import unittest
from package_and_publish import clean_staging_directory, validate_and_checksum

class PackageAndPublishTest(unittest.TestCase):
    def test_cleans_metadata_and_loose_files(self):
        with tempfile.TemporaryDirectory() as td:
            # 2 valid modules: agentguard-core and agentguard-parent
            core_dir = os.path.join(td, "io", "github", "amaljeevs", "agentguard-core", "0.2.0")
            parent_dir = os.path.join(td, "io", "github", "amaljeevs", "agentguard-parent", "0.2.0")
            os.makedirs(core_dir)
            os.makedirs(parent_dir)

            # Valid files
            core_pom = os.path.join(core_dir, "agentguard-core-0.2.0.pom")
            core_pom_asc = os.path.join(core_dir, "agentguard-core-0.2.0.pom.asc")
            core_jar = os.path.join(core_dir, "agentguard-core-0.2.0.jar")
            parent_pom = os.path.join(parent_dir, "agentguard-parent-0.2.0.pom")
            parent_pom_asc = os.path.join(parent_dir, "agentguard-parent-0.2.0.pom.asc")

            for path in [core_pom, core_pom_asc, core_jar, parent_pom, parent_pom_asc]:
                with open(path, "w") as f:
                    f.write("content")

            # Dirty files causing the Sonatype rejection:
            # 1. maven-metadata-local.xml directly under artifact folder (not in version folder)
            loose_metadata = os.path.join(td, "io", "github", "amaljeevs", "agentguard-core", "maven-metadata-local.xml")
            with open(loose_metadata, "w") as f:
                f.write("<metadata/>")

            # 2. _remote.repositories in version folder
            remote_repo = os.path.join(core_dir, "_remote.repositories")
            with open(remote_repo, "w") as f:
                f.write("remote")

            # 3. .zip file
            zip_file = os.path.join(td, "old.zip")
            with open(zip_file, "w") as f:
                f.write("zip")

            clean_staging_directory(td)

            # Assert dirty files are deleted
            self.assertFalse(os.path.exists(loose_metadata))
            self.assertFalse(os.path.exists(remote_repo))
            self.assertFalse(os.path.exists(zip_file))

            # Assert valid files are preserved
            self.assertTrue(os.path.exists(core_pom))
            self.assertTrue(os.path.exists(core_jar))
            self.assertTrue(os.path.exists(parent_pom))

            # Validate and checksum generates md5, sha1, sha256, sha512
            validate_and_checksum(td)
            self.assertTrue(os.path.exists(core_pom + ".md5"))
            self.assertTrue(os.path.exists(core_pom + ".sha1"))
            self.assertTrue(os.path.exists(core_pom + ".sha256"))
            self.assertTrue(os.path.exists(core_pom + ".sha512"))

if __name__ == "__main__":
    unittest.main()
