1. **Freeze current development**

   - Push and merge all open branches on **github.com/unclesp1d3r/opnFocus**.
   - Disable GitHub Actions temporarily (`Settings → Actions → Disable actions for this repo`) to avoid CI noise during the transfer.
   - Announce the freeze in the project README and in any internal chats so no new commits appear while files are being moved.

2. **Create a local, immutable backup**

   ```bash
   git clone --mirror git@github.com:unclesp1d3r/opnFocus.git opnFocus-backup.git
   tar -czf opnFocus-backup.tar.gz opnFocus-backup.git
   ```

3. **Update Go Module Path**

   - The Go module path will need to be updated from `github.com/unclesp1d3r/opnFocus` to `github.com/EvilBit-Labs/opnDossier` in all `.go` files and the `go.mod` file.
   - Perform a global find and replace for `unclesp1d3r/opnFocus` to `EvilBit-Labs/opnDossier`.

4. **Update Repository URLs**

   - All URLs pointing to the old repository in documentation, configuration files, and badges will need to be updated to the new repository URL. This includes the `README.md`, `.goreleaser.yaml`, and all files in the `docs/` directory.

5. **Rename the Binary**

   - The binary name should be changed from `opnfocus` to `opndossier` in the build process. This will require changes in `.goreleaser.yaml` (the `binary` field) and the `justfile`.

6. **Update Project Metadata**

   - The project name, owner, and other metadata in files like `.goreleaser.yaml` will need to be updated to reflect the new branding and ownership.

7. **Update GitHub Actions and CI/CD**

   - Review and update the `.github/workflows/*.yml` files. Specifically, check `ci.yml`, `codeql.yml`, `release.yml`, and `summary.yml` for any references to the old repository name or paths.
   - Check the `.github/dependabot.yml` file for any references to the old repository.

8. **Update Documentation Configuration**

   - Update the `repo_url` and `edit_uri` in `mkdocs.yml` to point to the new repository.

9. **Verify Other Configuration Files**

   - Check the `justfile` for any other references to the old project name or repository.
   - Review `package.json` for a repository URL or other metadata that needs to be updated.
