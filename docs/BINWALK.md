# Binwalk extraction

Common ZIP, TAR, gzip, bzip2 and XZ archives unpack without Binwalk. Raw images still receive hashing and bounded string checks. To inspect embedded filesystems such as SquashFS, configure Binwalk v3 in a **local Linux Docker engine**. Docker Desktop with Linux containers is suitable on Windows; WSL alone is not enough. A host-installed Binwalk v2/v3 is deliberately not used for extraction.

## Build the optional image

The upstream image includes Binwalk and helper extractors. Building it needs internet access and can take time and disk space. Review the upstream source and choose an upstream release or commit, rather than depending on a moving branch.

```text
git clone https://github.com/ReFirmLabs/binwalk.git binwalk-source
cd binwalk-source
git tag --list
git checkout <reviewed-release-tag-or-commit>
docker build -t firmguard-binwalk:3 .
docker run --rm --entrypoint binwalk firmguard-binwalk:3 --version
docker run --rm --entrypoint python3 firmguard-binwalk:3 --version
```

The adapter requires Binwalk's version output to start with `binwalk 3.` and requires Python 3 in the image. Binwalk v3's upstream Dockerfile includes extraction helpers. Installed extractors determine filesystem/format support; firmware encryption and vendor wrappers may still prevent extraction. No universal router support is claimed.

In PowerShell, before starting FirmGuard:

```powershell
$env:FIRMGUARD_BINWALK_IMAGE = 'firmguard-binwalk:3'
.\.venv\Scripts\python.exe scripts\doctor.py
.\start.ps1
```

On Linux/macOS:

```sh
export FIRMGUARD_BINWALK_IMAGE=firmguard-binwalk:3
.venv/bin/python scripts/doctor.py
sh start.sh
```

For reproducibility, set the variable to the `sha256:...` image ID printed by `docker image inspect --format '{{.Id}}' firmguard-binwalk:3`. Record the upstream commit and image ID in your evaluation notes. FirmGuard uses `--pull=never`; it does not build or download images for an upload. Reload the interface after changing configuration, then select the Binwalk checkbox for the raw image.

## Isolation and bounded export

The adapter uses a non-root UID, no network, no capabilities, no new privileges, a read-only container root, CPU/memory/process limits, and a 384 MiB output tmpfs. Only the input and the trusted container runner are mounted read-only. It does not mount the Docker socket or allow uploaded files to choose commands. Binwalk is invoked with v3 `--extract --matryoshka --threads 1 --directory` arguments. The runner does not run extracted firmware programs.

After extraction, the runner exports regular files through a TAR stream. Links and special files are excluded, reported as a skipped count, and never dereferenced for export. The host validates paths, entry counts and byte limits again and reads files virtually. The container and temporary input are removed on normal completion/error. A forced server termination can leave host temporary folders; the container has its own timeout and `--rm`. Keep Docker local; remote Docker bind mounts do not refer to the API host's filesystem.

The adapter has a 120-second wall timeout, an internal extractor timeout, 1.5 GiB container memory, one CPU, 64 processes and bounded output. Memory/format limits can make an otherwise valid image fail. Container isolation reduces exposure but is not a guarantee against vulnerabilities in Docker, the kernel or extractors. Use a disposable VM for truly untrusted firmware.

## Verify on an equipped machine

```powershell
$env:FIRMGUARD_BINWALK_IMAGE = 'firmguard-binwalk:3'
$env:FIRMGUARD_RUN_BINWALK_TEST = '1'
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_binwalk_live.py -v
```

This integration test constructs a tiny SquashFS in the configured image, extracts it through the real adapter, and checks that a credential finding is produced. It is skipped unless explicitly enabled. Adapter unit tests use a mocked Docker process and do **not** prove that a real Binwalk image works. See VERIFICATION.md for the checks actually run for this delivery.

Primary references: [upstream Binwalk](https://github.com/ReFirmLabs/binwalk), [v3 command-line arguments](https://github.com/ReFirmLabs/binwalk/blob/master/src/cliparser.rs), [upstream Dockerfile](https://github.com/ReFirmLabs/binwalk/blob/master/Dockerfile).
