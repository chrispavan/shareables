# APFS Unallocated PhotoRec Carver (Autopsy Jython module)

An Autopsy **Data Source Ingest Module** that extracts the unallocated space of
an APFS data source as one `.bin` file **per contiguous run** of unallocated
blocks, runs **PhotoRec** on each bin individually, and sorts the carved output
into folders **by MIME type**. Results are surfaced in the case as ingest inbox
messages and an HTML report, with SHA-256/MD5 hashing and a manifest CSV.

> ### ⚠️ Read this first: carving is CONTAINER-LEVEL, not per-volume
> APFS frees blocks at the **container / pool** level, not per volume. The
> Sleuth Kit does **not** build a per-volume unallocated set for APFS
> (`TskAutoDb::addFsInfoUnalloc()` returns early for APFS); instead the
> unallocated runs are attached to a synthetic **pool-level "Unallocated"
> volume**. This module therefore targets the **pool's `UNALLOC_BLOCKS`**
> layout files.
>
> **The volume dropdown in the settings panel is a label/context only — it does
> NOT scope the carving.** The carving is always container-wide. This caveat is
> repeated in the UI, the ingest messages, and the report.

---

## What it produces

Under the case module directory:

```
<Case>/ModuleOutput/APFS_Unalloc_PhotoRec_Carver/<dataSourceName>_<id>/
├── bins/                       # one .bin per contiguous unallocated run
│   └── unalloc_<layoutFileId>_off<byteStart>_len<byteLen>.bin
├── carved/                     # carved files sorted by MIME type
│   ├── image_jpeg/
│   ├── application_pdf/
│   ├── application_octet-stream/
│   └── ...
├── photorec_logs/              # every photorec.log, preserved
│   └── <binbase>.photorec.log
├── work/                       # PhotoRec recup_dir.N scratch (per bin)
├── manifest.csv                # source_bin, carved_file, mime, sha256
└── APFS_Unalloc_Carve_Report.html
```

`carved/<mime_top>_<subtype>/` — e.g. `image_jpeg`, `application_pdf`,
`application_octet-stream`. Carved file names are prefixed with their source
bin (`<binbase>__f0000001.jpg`) so files from different bins never collide.

---

## Requirements

- **Autopsy 4.x** (bundled Jython 2.7, JRE 17, The Sleuth Kit ~4.14).
- **PhotoRec** for Windows — the native `photorec_win.exe` from the
  [TestDisk/PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) distribution.
  No WSL. You provide the path to `photorec_win.exe` in the module settings.
- Native **Windows** runtime.

This module uses **only Java APIs through Jython** for native work (no
`pytsk3`, no `python-magic`, no `libmagic`). MIME detection uses
`java.nio.file.Files.probeContentType` with an extension-based fallback.

---

## Install

1. In Autopsy: **Tools → Python Plugins** (opens
   `%AppData%\autopsy\python_modules\`).
2. Create a subfolder, e.g. `APFS_Unalloc_PhotoRec_Carver`.
3. Copy `apfs_unalloc_photorec_carver.py` into that subfolder.
4. Restart Autopsy (or it will pick the module up on the next ingest dialog).

Full install path:

```
%AppData%\autopsy\python_modules\APFS_Unalloc_PhotoRec_Carver\apfs_unalloc_photorec_carver.py
```

(`selftest_logic.py` is a developer test — do **not** copy it into the Autopsy
modules folder.)

---

## Run

1. Add an **APFS image** to a case (see `VALIDATION.md` for the pre-flight
   check that a pool-level "Unallocated" node actually exists).
2. Run ingest: **Add Data Source → … → Configure Ingest Modules**, or
   **Tools → Run Ingest Modules** on an existing data source.
3. Select **"APFS Unalloc PhotoRec Carver"** and configure:
   - **Volume** — context/label only; does not scope carving.
   - **Path to `photorec_win.exe`** — required; the module refuses to start if
     it does not exist.
   - **PhotoRec command** — default
     `wholespace,fileopt,everything,enable,search` (the bin *is* free space, so
     `wholespace` is used; all file families enabled).
   - **Register carved files as derived files** — optional; off by default.
4. Start ingest. Watch the **Ingest Inbox** for progress and the final summary,
   and open the report from the **Reports** tree.

If no pool-level `UNALLOC_BLOCKS` node is found, the module posts a **WARNING**
explaining that TSK exposed no pool-level unallocated node and exits cleanly
(no fabricated data).

---

## Forensic notes

- The input image is treated as **read-only**. All output is written under the
  case module directory only.
- **SHA-256 and MD5** are computed for every `.bin` (single pass during
  extraction) and every carved file. The manifest CSV records
  `source_bin, carved_file, mime, sha256`; both hashes are written to the log.
- Every `photorec.log` is preserved under `photorec_logs/`.
- **Carved-file timestamps are recovery-time and are NOT trustworthy** —
  carving recovers content by signature from free space; original filesystem
  metadata (MAC times, names, paths) is gone. Derived files (if enabled) are
  registered with zeroed timestamps for this reason.

---

## How extraction maps runs to bins

Each pool-level `UNALLOC_BLOCKS` `LayoutFile` is a set of `TskFileRange`s. A
range's **file-relative** offset (what `LayoutFile.read()` expects) is the sum
of the byte lengths of all prior ranges, in sequence order. The module:

1. Sorts ranges by `getSequence()`.
2. Computes file-relative offsets as the running sum of prior `getByteLen()`
   (`range_file_offsets()` — unit-tested).
3. Writes **one `.bin` per range** by reading
   `LayoutFile.read(buf, fileOffset, len)` in an 8 MB chunked loop (a whole run
   is never loaded into memory).

The pure helpers (`range_file_offsets`, `bin_name`, `mime_to_folder`,
`is_photorec_artifact`, `carved_output_name`) are exercised by
`selftest_logic.py`, which parses the shipping source and tests the real
functions (run `python selftest_logic.py`).
