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

   - Update the `go.mod` file's module path specifically using a targeted sed command:

     ```bash
     sed -i 's|module github.com/unclesp1d3r/opnFocus|module github.com/EvilBit-Labs/opnDossier|' go.mod
     ```

   - Update all Go import paths in `.go` files using a find command combined with sed:

     ```bash
     find . -name "*.go" -type f -exec sed -i 's|github.com/unclesp1d3r/opnFocus|github.com/EvilBit-Labs/opnDossier|g' {} \;
     ```

   - Run `go mod tidy` to clean up dependencies:

     ```bash
     go mod tidy
     ```

4. **Update Repository URLs**

   - All URLs pointing to the old repository in documentation, configuration files, and badges will need to be updated to the new repository URL. This includes the `README.md`, `.goreleaser.yaml`, and all files in the `docs/` directory.

   - First, search for all instances of the old repository URL to understand the scope of changes:

     ```bash
     grep -r "github.com/unclesp1d3r/opnFocus" . --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=site --exclude-dir=opnFocus-backup.git
     ```

   - Update repository URLs in markdown, yaml, yml, and json files using find and sed:

     ```bash
     find . -type f \( -name "*.md" -o -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) \
       -not -path "./.git/*" \
       -not -path "./node_modules/*" \
       -not -path "./site/*" \
       -not -path "./opnFocus-backup.git/*" \
       -exec sed -i 's|github.com/unclesp1d3r/opnFocus|github.com/EvilBit-Labs/opnDossier|g' {} \;
     ```

   - Verify the changes by searching again to ensure all instances were updated:

     ```bash
     grep -r "github.com/unclesp1d3r/opnFocus" . --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=site --exclude-dir=opnFocus-backup.git
     ```

5. **Rename the Binary**

   - The binary name should be changed from `opnfocus` to `opndossier` in the build process. This will require changes in `.goreleaser.yaml` (the `binary` field) and the `justfile`.

   - First, search for all occurrences of the old binary name to understand the scope of changes:

     ```bash
     grep -r "opnfocus" . --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=site --exclude-dir=opnFocus-backup.git
     ```

   - Update binary name references in relevant file types using find and sed:

     ```bash
     find . -type f \( -name "*.md" -o -name "*.yaml" -o -name "*.yml" -o -name "justfile" -o -name "*.sh" \) \
       -not -path "./.git/*" \
       -not -path "./vendor/*" \
       -not -path "./node_modules/*" \
       -not -path "./site/*" \
       -not -path "./opnFocus-backup.git/*" \
       -exec sed -i 's/opnfocus/opndossier/g' {} \;
     ```

   - Verify the changes by searching again to ensure all instances were updated:

     ```bash
     grep -r "opnfocus" . --exclude-dir=.git --exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=site --exclude-dir=opnFocus-backup.git
     ```

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
