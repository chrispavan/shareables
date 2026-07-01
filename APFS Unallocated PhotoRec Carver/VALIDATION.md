# VALIDATION — APFS Unallocated PhotoRec Carver

This module cannot be run end-to-end outside Autopsy. This document describes
how to validate it inside Autopsy, plus the developer-side syntax/logic checks.

---

## 0. Developer pre-checks (no Autopsy needed)

From this folder:

```
python selftest_logic.py
```

Expected:

```
OK - 22 assertions passed across 6 helpers
```

This parses the **shipping source** (`apfs_unalloc_photorec_carver.py`) with
`ast`, extracts the pure helper functions, and tests the range→offset math,
MIME→folder mapping, bin naming, PhotoRec-artifact filtering, and carved-name
collision avoidance. It runs under Python 2.7 or Python 3.

Syntax (Python-2/Jython compatible) check:

```
python -m py_compile apfs_unalloc_photorec_carver.py
```

(The module imports Java/Autopsy classes, so it only *runs* inside Jython; the
compile check confirms it parses.)

---

## 1. CRITICAL pre-flight: confirm a pool-level Unallocated node exists

**Do this before trusting any output.** If TSK did not build a pool-level
unallocated set, there is nothing to carve and the module will (correctly) warn
and exit.

1. Create a new case and **Add Data Source → Disk Image or VM File**, pointing
   at your **APFS** image (e.g. `.dmg`/`.E01`/`.raw` containing an APFS
   container).
2. Let the default ingest finish (or cancel it; you only need the tree).
3. In the **Data Sources** tree, expand the image. For APFS you should see a
   **Pool** and, under it, volumes **plus** a synthetic **"Unallocated"**
   volume containing `Unalloc_*` layout files.
   - The unallocated node is **pool/container-level**, parallel to the
     volumes — **not** inside an individual APFS volume. This is expected and
     is the whole reason this module targets the pool.
4. Click an `Unalloc_*` file and confirm it has content/ranges.

If you do **not** see a pool-level "Unallocated" node with `Unalloc_*` files,
stop — the module has nothing to operate on, and that is a TSK/image property,
not a module bug. Running ingest will produce a WARNING in the Ingest Inbox.

---

## 2. Run the module

1. **Tools → Run Ingest Modules** on the APFS data source.
2. Enable **"APFS Unalloc PhotoRec Carver"**.
3. Set the **path to `photorec_win.exe`**. (Leaving it blank/invalid should
   make ingest fail to start with a clear message — verify this negative case
   too.)
4. Leave the PhotoRec command at its default
   (`wholespace,fileopt,everything,enable,search`).
5. Optionally tick **Register carved files as derived files**.
6. Start ingest.

---

## 3. Verify output

Open the case module directory:

```
<Case>/ModuleOutput/APFS_Unalloc_PhotoRec_Carver/<dataSourceName>_<id>/
```

Check, in order — **bins → carved → MIME folders**:

1. **`bins/`** contains one `.bin` per contiguous run, named
   `unalloc_<layoutFileId>_off<byteStart>_len<byteLen>.bin`. The number of bins
   should equal the total number of ranges across the pool's `Unalloc_*` files.
2. **`carved/`** contains MIME-named subfolders (`image_jpeg`,
   `application_pdf`, `application_octet-stream`, …). Each carved file is named
   `<binbase>__<photorecname>` (no collisions across bins).
3. **`photorec_logs/`** contains one preserved `photorec.log` per bin.
4. **`manifest.csv`** has header `source_bin,carved_file,mime,sha256` and one
   row per carved file. Spot-check a hash:
   - PowerShell: `Get-FileHash -Algorithm SHA256 <carved_file>` should match the
     `sha256` column.
5. **Report** — in the **Reports** tree, open
   *"APFS Unallocated PhotoRec Carve Report"* and confirm it states prominently
   that the unallocated set is **container/pool-level, not per-volume**, and
   that **carved-file timestamps are recovery-time and not trustworthy**.
6. **Ingest Inbox** — confirm a progress/summary INFO message with bin and
   carved-file counts.

---

## 4. Behavioral checks

| Scenario | Expected |
|---|---|
| Invalid/empty `photorec_win.exe` path | `startUp` raises `IngestModuleException`; ingest does not run. |
| APFS image with no pool-level Unalloc node | WARNING in inbox, `ProcessResult.OK`, no fabricated bins. |
| Cancel ingest mid-run | `dataSourceIngestIsCancelled()` is checked between runs and inside the read loop; PhotoRec is killed via `DataSourceIngestModuleProcessTerminator`. |
| One bad range/run | Logged as WARNING; the job continues with the remaining runs. |
| Volume dropdown changed | No effect on what is carved (label/context only) — output is identical. |
| Re-run on same data source | Existing carved/bin files may be overwritten (`REPLACE_EXISTING`); manifest/report regenerated. |

---

## 5. APIs flagged for verification in-environment

These are marked `# TODO: verify` in the source and should be confirmed against
the **installed** Autopsy/TSK build (signatures vary slightly across versions):

- `LayoutFile.read(byte[] buf, long offset, long len)` — extraction read loop.
- `ExecUtil.execute(ProcessBuilder, ProcessTerminator)` — PhotoRec invocation.
- `IngestMessage.createMessage(MessageType, source, subject)` — inbox messages
  (some builds accept a 4th details argument).
- `FileManager.addDerivedFile(...)` — only used when the optional
  derived-files checkbox is enabled; wrapped in try/except so a signature
  mismatch cannot break the job.
