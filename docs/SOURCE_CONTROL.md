# Source control and saved revisions

Application history is separate from Git. Every submitted file becomes a new analysis record with a revision number for its device/version label, exact-upload hash and scanner/advisory revisions. Raw uploads are not kept. The same label may be reused without overwriting results. Deleting a result does not reuse the revision number. SQLite storage is not a cryptographically signed audit log.

For code version control, initialize a Git repository in the extracted project if you do not already have one:

```text
git init
git add .
git commit -m "Add FirmGuard static firmware analyzer"
```

The included `.gitignore` excludes runtime databases, temporary analysis data, environments, node_modules and test/browser output. The release ZIP includes a built interface; it can be regenerated from committed frontend source and package-lock.json. If working from a clean Git checkout, run setup with the rebuild option.

Review changes with `git diff`, run tests before committing, and increment scanner/advisory revision identifiers when changing rule semantics. Keep raw confidential firmware outside source control. No Git repository or fabricated commit history is embedded in the release ZIP.
