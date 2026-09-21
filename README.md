# CobraSweep

Secure deletion and privacy sweep for PCs. Plain "delete" only unlinks a file — the bytes stay on disk for any recovery tool to find. CobraSweep overwrites data before deleting, and cleans the privacy-cluttering corners of the machine.

## Features

- **Secure shred**: overwrites files with random data (default 3 passes) plus a final zero pass, renames them to a random name, then unlinks — defeating common file-carving recovery.
- **Privacy sweep targets**: system temp folders, `~/.cache`, freedesktop thumbnails, trash bin, recently-used file lists, browser disk caches (Chrome/Chromium/Firefox/Edge/Brave), Windows Explorer thumbnail DBs, recent-document shortcuts and crash dumps.
- **Dry run by default**: `sweep` only reports what it *would* clean until you pass `--execute`. Add `--shred` to overwrite instead of plain-deleting sweep files.
- **Safety rails**: refuses to operate on `/`, your home directory itself, system roots, drive roots, or (on POSIX) anything outside home/temp. Symlinks are never followed.
- **Confirmation gate**: `shred` requires typing `shred` (or `--yes`) before anything is destroyed.
- **Clear reporting**: per-target item counts and bytes freed, with error summaries.
- **Pure stdlib**: Python 3.10+, zero dependencies. Linux/ChromeOS and Windows aware.

## Requirements

- Python 3.10+

## Run

See what a sweep would clean (safe, touches nothing):

```bash
python3 cobrasweep.py sweep
```

List the targets known on your platform:

```bash
python3 cobrasweep.py list
```

Actually clean, optionally only some targets, optionally with secure overwrite:

```bash
python3 cobrasweep.py sweep --execute
python3 cobrasweep.py sweep --execute --targets trash,recent-files
python3 cobrasweep.py sweep --execute --shred          # slower, but unrecoverable
```

Securely shred specific files (asks for confirmation):

```bash
python3 cobrasweep.py shred secret.docx old-backup.zip
python3 cobrasweep.py shred --passes 7 --yes finances.xlsx
```

## Notes

- Overwriting guarantees apply to spinning disks and local filesystems. On SSDs with wear-leveling, copy-on-write filesystems, or cloud-synced folders, physical erasure can never be fully guaranteed — use full-disk encryption as the real defense there.
- Files in use by running applications are skipped and reported as errors.

## Tests

```bash
python3 -m unittest discover -s tests
```
