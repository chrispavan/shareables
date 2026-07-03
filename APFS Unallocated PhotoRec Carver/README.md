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
├── bins/                       # empty by default (see cleanup below)
│   └── unalloc_<layoutFileId>_off<byteStart>_len<byteLen>.bin   # only if "keep bins" is ticked
├── carved/                     # carved files sorted by MIME type
│   ├── image_jpeg/
│   ├── application_pdf/
│   ├── application_octet-stream/
│   └── ...
├── photorec_logs/              # every photorec.log, preserved
│   └── <binbase>.photorec.log
├── manifest.csv                # source_bin, carved_file, mime, sha256
├── bins_manifest.csv           # bin_name, byte_start, byte_len, md5, sha256
└── APFS_Unalloc_Carve_Report.html
```

`carved/<mime_top>_<subtype>/` — e.g. `image_jpeg`, `application_pdf`,
`application_octet-stream`. Carved file names are prefixed with their source
bin (`<binbase>__f0000001.jpg`) so files from different bins never collide.

### Cleanup / disk usage

To avoid bloating the case with useless intermediate data, the module cleans
up **as it goes**:

- Each `.bin` is a full raw copy of unallocated space. After its bin is carved,
  the `.bin` is **deleted by default** (its MD5/SHA-256 are preserved in
  `bins_manifest.csv` for provenance). Tick **"Keep extracted .bin files"** in
  settings to retain them in `bins/` instead (uses far more disk).
- The per-bin PhotoRec scratch dir (`recup_dir.N`, thumbnails, `report.xml`) is
  **always** removed after its carved files are sorted out; the `work/` tree is
  removed entirely at the end. Only the carved files, logs, manifests, and
  report remain.

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
   - **Path to `photorec_win.exe`** — the **first field** in the panel.
     Pre-filled to `C:\tools\testdisk-7.2\photorec_win.exe` as a convenience;
     edit it (or use **Browse…**) to point at wherever you unpacked the
     TestDisk/PhotoRec distribution. There is no bundled PhotoRec. The module
     refuses to start (`IngestModuleException`) if the path does not exist, so
     the default only helps if PhotoRec really is installed there.
   - **File types to keep** — a checklist of supported families (see below).
     **The default is WAV only.** PhotoRec carves *all* types; this selection
     is applied as an **output filter by MIME** — only the ticked types are
     moved into `carved/` and the manifest, the rest are discarded with the
     scratch dir. Use *Select all* / *Select none (WAV default)* for the
     extremes. (Per-family selection is done on our side, not in PhotoRec,
     because PhotoRec's per-family `fileopt` tokens vary by build and version
     and can't be hardcoded reliably — some builds reject `wav`.)
   - **Advanced: raw PhotoRec `/cmd` override** — blank by default. If you type
     a raw command tail here it is used verbatim, and no MIME filter is applied
     (you're in full control of PhotoRec, incl. its ~480-family `fileopt` set).
     Otherwise PhotoRec runs the fixed command
     `partition_none,wholespace,fileopt,everything,enable,search`:
     `partition_none` treats each bin as **non-partitioned raw media** so
     PhotoRec doesn't false-detect a partition table / filesystem in the raw
     unallocated data; `wholespace` carves the whole bin.
   - **Register carved files as derived files** — optional; off by default.
   - **Keep extracted .bin files after carving** — optional; **off by default**
     (bins are deleted as carving proceeds to save disk; see *Cleanup* above).
4. Start ingest. Watch the **Ingest Inbox** for progress and the final summary,
   and open the report from the **Reports** tree.

If no pool-level `UNALLOC_BLOCKS` node is found, the module posts a **WARNING**
explaining that TSK exposed no pool-level unallocated node and exits cleanly
(no fabricated data).

---

## Supported file types → MIME → output folder

**The default keep-set is WAV only.** PhotoRec carves all types; tick
additional families to keep them. Each kept file is sorted into a
`carved/<mime>/` folder named from its detected MIME type. The families the
checklist exposes (matched against each carved file's detected MIME):

| PhotoRec key | MIME type | Description | Output folder |
|---|---|---|---|
| `wav` **(default)** | `audio/x-wav` | WAV / RIFF audio | `carved/audio_x-wav/` |
| `mp3` | `audio/mpeg` | MP3 audio | `carved/audio_mpeg/` |
| `ogg` | `audio/ogg` | Ogg Vorbis audio | `carved/audio_ogg/` |
| `flac` | `audio/flac` | FLAC lossless audio | `carved/audio_flac/` |
| `au` | `audio/basic` | Sun/NeXT AU audio | `carved/audio_basic/` |
| `mid` | `audio/midi` | MIDI | `carved/audio_midi/` |
| `aac` | `audio/aac` | AAC audio | `carved/audio_aac/` |
| `wma` | `audio/x-ms-wma` | Windows Media Audio (ASF) | `carved/audio_x-ms-wma/` |
| `mov` | `video/quicktime` | QuickTime / MP4 / 3GP (MOV family) | `carved/video_quicktime/` |
| `mp4` | `video/mp4` | MP4 video | `carved/video_mp4/` |
| `avi` | `video/x-msvideo` | AVI (RIFF video) | `carved/video_x-msvideo/` |
| `mkv` | `video/x-matroska` | Matroska / WebM | `carved/video_x-matroska/` |
| `mpg` | `video/mpeg` | MPEG program stream | `carved/video_mpeg/` |
| `asf` | `video/x-ms-asf` | Windows Media Video (ASF) | `carved/video_x-ms-asf/` |
| `flv` | `video/x-flv` | Flash video | `carved/video_x-flv/` |
| `jpg` | `image/jpeg` | JPEG image | `carved/image_jpeg/` |
| `png` | `image/png` | PNG image | `carved/image_png/` |
| `gif` | `image/gif` | GIF image | `carved/image_gif/` |
| `bmp` | `image/bmp` | BMP image | `carved/image_bmp/` |
| `tif` | `image/tiff` | TIFF image | `carved/image_tiff/` |
| `ico` | `image/x-icon` | Windows icon | `carved/image_x-icon/` |
| `psd` | `image/vnd.adobe.photoshop` | Photoshop PSD | `carved/image_vnd.adobe.photoshop/` |
| `cr2` | `image/x-canon-cr2` | Canon RAW (CR2) | `carved/image_x-canon-cr2/` |
| `nef` | `image/x-nikon-nef` | Nikon RAW (NEF) | `carved/image_x-nikon-nef/` |
| `orf` | `image/x-olympus-orf` | Olympus RAW (ORF) | `carved/image_x-olympus-orf/` |
| `raf` | `image/x-fuji-raf` | Fujifilm RAW (RAF) | `carved/image_x-fuji-raf/` |
| `rw2` | `image/x-panasonic-rw2` | Panasonic RAW (RW2) | `carved/image_x-panasonic-rw2/` |
| `heic` | `image/heic` | HEIF/HEIC image | `carved/image_heic/` |
| `webp` | `image/webp` | WebP image | `carved/image_webp/` |
| `pdf` | `application/pdf` | PDF document | `carved/application_pdf/` |
| `doc` | `application/msword` | MS Office OLE (doc/xls/ppt/msi) | `carved/application_msword/` |
| `rtf` | `application/rtf` | Rich Text Format | `carved/application_rtf/` |
| `txt` | `text/plain` | Plain text (and many text formats) | `carved/text_plain/` |
| `html` | `text/html` | HTML | `carved/text_html/` |
| `xml` | `application/xml` | XML | `carved/application_xml/` |
| `zip` | `application/zip` | ZIP (also docx/xlsx/pptx/odt/epub/jar) | `carved/application_zip/` |
| `gz` | `application/gzip` | gzip | `carved/application_gzip/` |
| `bz2` | `application/x-bzip2` | bzip2 | `carved/application_x-bzip2/` |
| `7z` | `application/x-7z-compressed` | 7-Zip | `carved/application_x-7z-compressed/` |
| `rar` | `application/vnd.rar` | RAR | `carved/application_vnd.rar/` |
| `tar` | `application/x-tar` | tar | `carved/application_x-tar/` |
| `xz` | `application/x-xz` | xz | `carved/application_x-xz/` |
| `cab` | `application/vnd.ms-cab-compressed` | Microsoft Cabinet | `carved/application_vnd.ms-cab-compressed/` |
| `sqlite` | `application/x-sqlite3` | SQLite database | `carved/application_x-sqlite3/` |
| `mdb` | `application/x-msaccess` | MS Access (MDB/ACCDB) | `carved/application_x-msaccess/` |
| `dbf` | `application/x-dbf` | dBASE | `carved/application_x-dbf/` |
| `pst` | `application/vnd.ms-outlook` | Outlook PST/OST | `carved/application_vnd.ms-outlook/` |
| `evt` | `application/x-ms-evt` | Windows Event Log (legacy) | `carved/application_x-ms-evt/` |
| `evtx` | `application/x-ms-evtx` | Windows Event Log (XML) | `carved/application_x-ms-evtx/` |
| `exe` | `application/vnd.microsoft.portable-executable` | Windows PE | `carved/application_vnd.microsoft.portable-executable/` |
| `elf` | `application/x-elf` | ELF binary | `carved/application_x-elf/` |
| `dex` | `application/vnd.android.dex` | Android DEX | `carved/application_vnd.android.dex/` |
| `class` | `application/java-vm` | Java class | `carved/application_java-vm/` |
| `iso` | `application/x-iso9660-image` | ISO 9660 | `carved/application_x-iso9660-image/` |
| `vmdk` | `application/x-vmdk` | VMware disk | `carved/application_x-vmdk/` |
| `swf` | `application/x-shockwave-flash` | Shockwave Flash | `carved/application_x-shockwave-flash/` |
| `gpx` | `application/gpx+xml` | GPS exchange | `carved/application_gpx+xml/` |

Notes:
- The **MIME type** column is what the filter matches against. PhotoRec runs a
  single fixed command that carves everything
  (`partition_none,wholespace,fileopt,everything,enable,search`); a carved file
  is **kept** only if its detected MIME is in your selected set, otherwise it is
  discarded with the scratch dir. The **PhotoRec key** is shown for reference.
- The **output folder** is derived from each carved file's extension→MIME (the
  table above; PhotoRec names files by signature) and only falls back to
  `java.nio.file.Files.probeContentType` for unknown extensions, so a file may
  land in a slightly different folder than its family
  row if the OS detector disagrees. Unknown types go to
  `carved/application_octet-stream/`.
- PhotoRec's full signature set is ~480 families. Anything not listed here is
  reachable via the **Advanced raw `/cmd` override** field.

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
