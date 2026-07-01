# -*- coding: utf-8 -*-
#
# apfs_unalloc_photorec_carver.py
#
# Autopsy Python (Jython 2.7) Data Source Ingest Module.
#
# Purpose
# -------
# Extract the *pool/container-level* unallocated space of an APFS data source
# as one .bin file per contiguous run of unallocated blocks, run PhotoRec on
# each bin individually, and sort the carved output into folders by MIME type.
#
# CRITICAL DOMAIN CONSTRAINT (read this before changing anything)
# ---------------------------------------------------------------
# APFS frees blocks at the CONTAINER / POOL level, not per volume. The Sleuth
# Kit does NOT build a per-volume unallocated set for APFS
# (TskAutoDb::addFsInfoUnalloc() returns early for APFS); the unallocated runs
# are attached to a synthetic POOL-LEVEL unallocated volume. Therefore this
# module targets the POOL's UNALLOC_BLOCKS layout files, never a single
# volume's. The volume dropdown in the settings panel is a CONTEXT/LABEL ONLY
# and does not scope the carving. This is stated in the UI and in the report.
#
# Environment
# -----------
# * Jython 2.7 / Python 2 syntax ONLY (no f-strings, % formatting only).
# * No CPython C-extensions (no pytsk3 / python-magic / libmagic). All native
#   work goes through Java APIs via Jython.
# * Autopsy 4.x, JRE 17, bundled Jython 2.7, The Sleuth Kit ~4.14.
# * Native Windows runtime; PhotoRec is photorec_win.exe (no WSL).
#
# Install location
# ----------------
#   %AppData%\autopsy\python_modules\APFS_Unalloc_PhotoRec_Carver\
#       apfs_unalloc_photorec_carver.py
#
# Autopsy discovers factories by scanning module source text for the string
# "IngestModuleFactoryAdapter", so the factory subclasses it directly below.

import os
import csv
import jarray
import inspect
import traceback

# --- Java / Autopsy imports (resolved by Jython at runtime) ------------------
from java.lang import ProcessBuilder
from java.lang import System
from java.lang import IllegalArgumentException
from java.io import File
from java.io import FileOutputStream
from java.io import FileInputStream
from java.security import MessageDigest
from java.util.logging import Level
from java.nio.file import Files
from java.nio.file import Paths
from java.nio.file import StandardCopyOption

from javax.swing import JPanel
from javax.swing import JComboBox
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTextField
from javax.swing import JFileChooser
from javax.swing import JCheckBox
from javax.swing import BoxLayout
from javax.swing import DefaultComboBoxModel
from javax.swing import BorderFactory
from java.awt import Dimension

from org.sleuthkit.datamodel import TskData
from org.sleuthkit.datamodel import TskCoreException
from org.sleuthkit.datamodel import Volume
from org.sleuthkit.datamodel import LayoutFile

from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest.IngestModule import ProcessResult
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices

from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import ExecUtil
# DataSourceIngestModuleProcessTerminator is a top-level class in the .ingest
# package (it implements ExecUtil.ProcessTerminator); it is NOT nested inside
# ExecUtil. Importing it from ExecUtil raises ImportError.
from org.sleuthkit.autopsy.ingest import DataSourceIngestModuleProcessTerminator

# FileTypeDetector operates on AbstractFile, not on a path on disk, so it is
# only usable here once carved files are added back into the case as derived
# files. We keep the import for that optional path; the on-disk MIME detection
# uses java.nio.file.Files.probeContentType (see detect_mime_for_path).
try:
    from org.sleuthkit.autopsy.modules.filetypeid import FileTypeDetector
except ImportError:
    FileTypeDetector = None


# Module-level constants.
MODULE_NAME = "APFS Unalloc PhotoRec Carver"
MODULE_VERSION = "1.0.1"

# Read buffer for extraction and hashing: large enough to be efficient, small
# enough that we never load a whole unallocated run into memory.
READ_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB

# Default PhotoRec search command fragment. The bin IS free space, so we use
# "wholespace" (there is no live FS to compute free space from). "fileopt,
# everything,enable" turns on all file families; "search" starts the carve.
DEFAULT_PHOTOREC_CMD = "wholespace,fileopt,everything,enable,search"

DEFAULT_MIME = "application/octet-stream"


# =============================================================================
# Pure-logic helpers
# -----------------------------------------------------------------------------
# These functions have NO dependency on Java or Autopsy and are deliberately
# kept side-effect-free (or trivially so) so the range->offset math, the
# MIME->folder mapping and the bin naming can be unit-checked independently
# (see selftest_logic.py). Do not add Java calls here.
# =============================================================================

def range_file_offsets(ordered_lengths):
    """Given the byte lengths of a layout file's ranges in sequence order,
    return the file-relative start offset of each range (the running sum of
    all prior lengths). LayoutFile.read() takes a file-relative offset, and a
    range's offset is simply the sum of the lengths of the ranges before it.

    >>> range_file_offsets([100, 50, 200])
    [0, 100, 150]
    """
    offsets = []
    acc = 0
    for length in ordered_lengths:
        offsets.append(acc)
        acc = acc + int(length)
    return offsets


def bin_name(layout_file_id, byte_start, byte_len):
    """Name for the .bin holding one contiguous unallocated run.

    >>> bin_name(7, 1048576, 4096)
    'unalloc_7_off1048576_len4096.bin'
    """
    return "unalloc_%s_off%s_len%s.bin" % (layout_file_id, byte_start, byte_len)


def mime_to_folder(mime):
    """Map a MIME type to a filesystem-safe folder name 'top_subtype'.

    >>> mime_to_folder("image/jpeg")
    'image_jpeg'
    >>> mime_to_folder("application/pdf")
    'application_pdf'
    >>> mime_to_folder("text/plain; charset=utf-8")
    'text_plain'
    >>> mime_to_folder(None)
    'application_octet-stream'
    >>> mime_to_folder("weirdvalue")
    'weirdvalue_unknown'
    """
    if not mime:
        mime = DEFAULT_MIME
    mime = mime.strip().lower()
    if ";" in mime:
        mime = mime.split(";", 1)[0].strip()
    parts = mime.split("/", 1)
    if len(parts) == 2 and parts[0] and parts[1]:
        top, sub = parts[0], parts[1]
    else:
        top, sub = (parts[0] if parts and parts[0] else "application"), "unknown"
    raw = "%s_%s" % (top, sub)
    safe_chars = []
    for ch in raw:
        if ch.isalnum() or ch in ("_", "-", ".", "+"):
            safe_chars.append(ch)
        else:
            safe_chars.append("_")
    out = "".join(safe_chars)
    if not out:
        out = "application_octet-stream"
    return out


def is_photorec_artifact(filename):
    """True for PhotoRec bookkeeping files that should NOT be treated as
    carved evidence: the log, the XML report, and thumbnail files (named
    't<digits>...'). The photorec.log is preserved separately by the caller.

    >>> is_photorec_artifact("photorec.log")
    True
    >>> is_photorec_artifact("report.xml")
    True
    >>> is_photorec_artifact("t1000000.jpg")
    True
    >>> is_photorec_artifact("f0000001.jpg")
    False
    """
    base = filename.strip().lower()
    if base in ("photorec.log", "report.xml"):
        return True
    if len(base) >= 2 and base[0] == "t" and base[1].isdigit():
        return True
    return False


def carved_output_name(bin_base, original_name):
    """Carved files from different bins share PhotoRec's sequential naming
    (f0000001.jpg ...), so prefix with the source bin base to avoid collisions
    when many bins feed one MIME folder.

    >>> carved_output_name("unalloc_7_off0_len4096", "f0000001.jpg")
    'unalloc_7_off0_len4096__f0000001.jpg'
    """
    return "%s__%s" % (bin_base, original_name)


def manifest_header():
    return ["source_bin", "carved_file", "mime", "sha256"]


# =============================================================================
# Factory
# =============================================================================

class ApfsUnallocCarverFactory(IngestModuleFactoryAdapter):

    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return ("Extracts APFS pool/container-level unallocated runs to one "
                ".bin per run, carves each with PhotoRec, and sorts carved "
                "files by MIME type. Carving is container-wide, NOT "
                "volume-specific.")

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return ApfsUnallocCarverModule(ingestOptions)

    # ----- Ingest job settings / panel -----
    def getDefaultIngestJobSettings(self):
        return ApfsUnallocCarverSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, ApfsUnallocCarverSettings):
            # Defensive: Autopsy should always hand back our settings type.
            settings = ApfsUnallocCarverSettings()
        return ApfsUnallocCarverSettingsPanel(settings)


# =============================================================================
# Ingest job settings
# =============================================================================

class ApfsUnallocCarverSettings(IngestModuleIngestJobSettings):
    # Required by IngestModuleIngestJobSettings (serializable).
    serialVersionUID = long(1)

    def __init__(self):
        # Selected volume id is a LABEL/context only; it does NOT scope carving.
        self.selected_volume_id = -1
        self.selected_volume_label = "(container-wide)"
        # Path to photorec_win.exe.
        self.photorec_path = ""
        # PhotoRec file-family / search command fragment.
        self.photorec_cmd = DEFAULT_PHOTOREC_CMD
        # Optionally register carved files as derived files in the case.
        self.add_derived_files = False

    def getVersionNumber(self):
        return self.serialVersionUID

    # --- typed accessors (defensive against unpickled-without-attr cases) ---
    def getSelectedVolumeId(self):
        return getattr(self, "selected_volume_id", -1)

    def setSelectedVolume(self, vol_id, label):
        self.selected_volume_id = vol_id
        self.selected_volume_label = label

    def getSelectedVolumeLabel(self):
        return getattr(self, "selected_volume_label", "(container-wide)")

    def getPhotorecPath(self):
        return getattr(self, "photorec_path", "")

    def setPhotorecPath(self, path):
        self.photorec_path = path

    def getPhotorecCmd(self):
        cmd = getattr(self, "photorec_cmd", DEFAULT_PHOTOREC_CMD)
        return cmd if cmd else DEFAULT_PHOTOREC_CMD

    def setPhotorecCmd(self, cmd):
        self.photorec_cmd = cmd

    def getAddDerivedFiles(self):
        return getattr(self, "add_derived_files", False)

    def setAddDerivedFiles(self, flag):
        self.add_derived_files = bool(flag)


# =============================================================================
# Settings panel
# =============================================================================

class ApfsUnallocCarverSettingsPanel(IngestModuleIngestJobSettingsPanel):

    def __init__(self, settings):
        self.local_settings = settings
        self._volume_ids = []   # parallel list to combo box entries
        self.initComponents()
        self.customizeComponents()

    # --- helpers to walk the case for Volume objects -----------------------
    def _collect_volumes(self, content, found):
        """Recursively gather Volume objects under a Content node."""
        try:
            children = content.getChildren()
        except Exception:
            children = []
        for child in children:
            try:
                if isinstance(child, Volume):
                    found.append(child)
                # Recurse: volumes live under volume systems / pools.
                self._collect_volumes(child, found)
            except Exception:
                # Never let one bad node break panel construction.
                continue

    def _load_volumes(self):
        volumes = []
        try:
            case = Case.getCurrentCase()
            for ds in case.getDataSources():
                self._collect_volumes(ds, volumes)
        except Exception:
            # No open case / no data sources yet -> empty dropdown is fine.
            volumes = []
        return volumes

    def initComponents(self):
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # Disclaimer (container-level carving).
        self.disclaimer = JLabel(
            "<html><b>Note:</b> APFS frees blocks at the container/pool level. "
            "Unallocated carving here is <u>container-wide, not volume-specific</u>. "
            "The volume choice below is a label/context only.</html>")
        self.add(self.disclaimer)
        self.add(JLabel(" "))

        # Volume selector (label/context only).
        self.add(JLabel("Volume (context/label only - does NOT scope carving):"))
        self.volumeCombo = JComboBox()
        self.volumeCombo.setMaximumSize(Dimension(600, 28))
        self.add(self.volumeCombo)
        self.add(JLabel(" "))

        # PhotoRec path + chooser.
        self.add(JLabel("Path to photorec_win.exe:"))
        self.photorecField = JTextField(40)
        self.photorecField.setMaximumSize(Dimension(600, 28))
        self.add(self.photorecField)
        self.browseButton = JButton("Browse...",
                                     actionPerformed=self.onBrowse)
        self.add(self.browseButton)
        self.add(JLabel(" "))

        # PhotoRec command fragment.
        self.add(JLabel("PhotoRec command (file families / search):"))
        self.cmdField = JTextField(40)
        self.cmdField.setMaximumSize(Dimension(600, 28))
        self.add(self.cmdField)
        self.add(JLabel(" "))

        # Derived files checkbox.
        self.derivedCheck = JCheckBox(
            "Register carved files as derived files in the case",
            actionPerformed=self.onDerivedToggle)
        self.add(self.derivedCheck)

    def customizeComponents(self):
        # Populate volume combo.
        model = DefaultComboBoxModel()
        self._volume_ids = []
        model.addElement("(container-wide - no specific volume)")
        self._volume_ids.append(-1)
        for vol in self._load_volumes():
            try:
                vid = vol.getId()
                desc = vol.getDescription()
            except Exception:
                continue
            label = "vol id=%s  %s" % (vid, desc)
            model.addElement(label)
            self._volume_ids.append(vid)
        self.volumeCombo.setModel(model)

        # Restore selection if present.
        sel_id = self.local_settings.getSelectedVolumeId()
        if sel_id in self._volume_ids:
            self.volumeCombo.setSelectedIndex(self._volume_ids.index(sel_id))

        self.volumeCombo.addActionListener(
            ActionListenerProxy(self.onVolumeChange))

        # Restore other fields.
        self.photorecField.setText(self.local_settings.getPhotorecPath())
        self.cmdField.setText(self.local_settings.getPhotorecCmd())
        self.derivedCheck.setSelected(self.local_settings.getAddDerivedFiles())

        # Persist text fields on focus changes / typing via document listeners
        # is overkill here; we read them in the event handlers and on the
        # combo change. To be safe, also capture on every action.

    # --- event handlers ----------------------------------------------------
    def onVolumeChange(self, event):
        idx = self.volumeCombo.getSelectedIndex()
        if idx < 0 or idx >= len(self._volume_ids):
            return
        vid = self._volume_ids[idx]
        label = self.volumeCombo.getSelectedItem()
        self.local_settings.setSelectedVolume(vid, label)
        # Capture the free-text fields too while we have an event.
        self._capture_text_fields()

    def onBrowse(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        ret = chooser.showOpenDialog(self)
        if ret == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            self.photorecField.setText(path)
            self.local_settings.setPhotorecPath(path)

    def onDerivedToggle(self, event):
        self.local_settings.setAddDerivedFiles(self.derivedCheck.isSelected())
        self._capture_text_fields()

    def _capture_text_fields(self):
        self.local_settings.setPhotorecPath(self.photorecField.getText())
        self.local_settings.setPhotorecCmd(self.cmdField.getText())

    def getSettings(self):
        # Autopsy calls this to persist the panel's settings.
        self._capture_text_fields()
        idx = self.volumeCombo.getSelectedIndex()
        if 0 <= idx < len(self._volume_ids):
            self.local_settings.setSelectedVolume(
                self._volume_ids[idx], self.volumeCombo.getSelectedItem())
        self.local_settings.setAddDerivedFiles(self.derivedCheck.isSelected())
        return self.local_settings


# Small action-listener proxy so we can attach a Python method as a listener.
# (Some Jython/Swing combos dislike addActionListener(self.method) directly.)
from java.awt.event import ActionListener


class ActionListenerProxy(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback(event)


# =============================================================================
# Data source ingest module
# =============================================================================

class ApfsUnallocCarverModule(DataSourceIngestModule):

    def __init__(self, settings):
        self.local_settings = settings
        self.context = None
        self.logger = Logger.getLogger(MODULE_NAME)
        self.services = IngestServices.getInstance()
        self._sha256_digest = None  # reused MessageDigest

    def log(self, level, msg):
        self.logger.logp(level, self.__class__.__name__,
                         inspect.stack()[1][3], msg)

    # ----- lifecycle -------------------------------------------------------
    def startUp(self, context):
        self.context = context
        photorec = self.local_settings.getPhotorecPath()
        if not photorec or not os.path.exists(photorec):
            raise IngestModuleException(
                "PhotoRec executable not found at: %s. Set a valid path to "
                "photorec_win.exe in the module settings." % (photorec,))
        self.log(Level.INFO, "APFS Unalloc PhotoRec Carver starting; "
                 "photorec=%s" % (photorec,))

    def process(self, dataSource, progressBar):
        try:
            return self._process_impl(dataSource, progressBar)
        except Exception:
            # Last-ditch guard: log full trace, report OK so the rest of the
            # ingest pipeline is not aborted by an unexpected error here.
            self.log(Level.SEVERE,
                     "Unhandled error in process(): %s" % (traceback.format_exc(),))
            self._post(IngestMessage.MessageType.ERROR,
                       "APFS unalloc carving failed",
                       "An unexpected error occurred; see the log. Other "
                       "ingest modules were not affected.")
            return ProcessResult.OK

    # ----- main implementation --------------------------------------------
    def _process_impl(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()

        # 1. Discover pool-level UNALLOC_BLOCKS layout files.
        layout_files = []
        self._collect_unalloc_layout_files(dataSource, layout_files)

        if not layout_files:
            msg = ("No pool-level UNALLOC_BLOCKS node was exposed by The Sleuth "
                   "Kit for this data source. For APFS, unallocated space is a "
                   "container/pool-level synthetic 'Unallocated' volume; if TSK "
                   "did not build one, there is nothing to carve. Exiting "
                   "cleanly without fabricating data.")
            self.log(Level.WARNING, msg)
            self._post(IngestMessage.MessageType.WARNING,
                       "No pool-level unallocated set found", msg)
            return ProcessResult.OK

        # 2. Prepare output directories under the case module directory.
        ds_dir, bins_dir, carved_dir, work_dir, logs_dir = \
            self._prepare_dirs(dataSource)
        manifest_path = os.path.join(ds_dir, "manifest.csv")
        manifest_rows = []

        # 3. Count total ranges for a deterministic progress bar.
        total_ranges = 0
        for lf in layout_files:
            try:
                total_ranges = total_ranges + len(list(lf.getRanges()))
            except Exception:
                self.log(Level.WARNING,
                         "Could not read ranges for layout file id=%s" %
                         (self._safe_id(lf),))
        if total_ranges <= 0:
            total_ranges = 1
        progressBar.switchToDeterminate(total_ranges)

        carved_total = 0
        bins_written = 0
        done_units = 0

        # 4. Per layout file -> per range: extract bin, carve, sort.
        for lf in layout_files:
            if self.context.dataSourceIngestIsCancelled():
                break
            try:
                ranges = list(lf.getRanges())
            except Exception:
                self.log(Level.WARNING,
                         "Skipping layout file id=%s (getRanges failed): %s" %
                         (self._safe_id(lf), traceback.format_exc()))
                continue

            # Order ranges by sequence and compute file-relative offsets.
            try:
                ranges_sorted = sorted(ranges, key=lambda r: r.getSequence())
            except Exception:
                ranges_sorted = ranges
            lengths = [r.getByteLen() for r in ranges_sorted]
            file_offsets = range_file_offsets(lengths)

            lf_id = self._safe_id(lf)

            for idx, rng in enumerate(ranges_sorted):
                if self.context.dataSourceIngestIsCancelled():
                    break
                try:
                    self._process_one_range(
                        lf, lf_id, rng, file_offsets[idx],
                        bins_dir, carved_dir, work_dir, logs_dir,
                        manifest_rows)
                    bins_written = bins_written + 1
                except Exception:
                    # One bad run must not abort the whole job.
                    self.log(Level.WARNING,
                             "Range carve failed (layout id=%s seq=%s): %s" %
                             (lf_id, self._safe_seq(rng), traceback.format_exc()))
                done_units = done_units + 1
                progressBar.progress(min(done_units, total_ranges))

        carved_total = len(manifest_rows)

        # 5. Write manifest and report; surface in the case.
        try:
            self._write_manifest(manifest_path, manifest_rows)
        except Exception:
            self.log(Level.WARNING,
                     "Failed writing manifest: %s" % (traceback.format_exc(),))

        report_path = os.path.join(ds_dir, "APFS_Unalloc_Carve_Report.html")
        try:
            self._write_report(report_path, dataSource, bins_written,
                                carved_total, manifest_path)
            try:
                Case.getCurrentCase().addReport(
                    report_path, MODULE_NAME,
                    "APFS Unallocated PhotoRec Carve Report")
            except Exception:
                self.log(Level.WARNING,
                         "addReport failed: %s" % (traceback.format_exc(),))
        except Exception:
            self.log(Level.WARNING,
                     "Failed writing report: %s" % (traceback.format_exc(),))

        summary = ("APFS container-wide unallocated carving complete. "
                   "Bins written: %s. Carved files: %s. Output: %s" %
                   (bins_written, carved_total, carved_dir))
        self.log(Level.INFO, summary)
        self._post(IngestMessage.MessageType.INFO,
                   "APFS unalloc carving complete", summary)
        return ProcessResult.OK

    # ----- per-range work --------------------------------------------------
    def _process_one_range(self, lf, lf_id, rng, file_offset,
                           bins_dir, carved_dir, work_dir, logs_dir,
                           manifest_rows):
        byte_start = rng.getByteStart()
        byte_len = rng.getByteLen()
        name = bin_name(lf_id, byte_start, byte_len)
        bin_path = os.path.join(bins_dir, name)
        bin_base = name[:-4] if name.endswith(".bin") else name  # drop .bin

        # Extract this run into a .bin, hashing as we go (single pass).
        md5_hex, sha256_hex = self._extract_range_to_bin(
            lf, file_offset, byte_len, bin_path)
        self.log(Level.INFO,
                 "Wrote bin %s (%s bytes) md5=%s sha256=%s" %
                 (name, byte_len, md5_hex, sha256_hex))

        # Carve this bin with PhotoRec into a per-bin work dir.
        bin_work = os.path.join(work_dir, bin_base)
        self._ensure_dir(bin_work)
        recup_prefix = os.path.join(bin_work, "recup_dir")

        exit_code = self._run_photorec(bin_path, recup_prefix)
        self.log(Level.INFO, "PhotoRec exit=%s for %s" % (exit_code, name))

        # Preserve the photorec.log (forensic record).
        self._preserve_photorec_log(bin_work, logs_dir, bin_base)

        # Sort carved output by MIME into carved/<mime_folder>/.
        n_carved = self._sort_carved_output(
            bin_work, carved_dir, bin_base, name, lf, manifest_rows)
        self.log(Level.INFO,
                 "Sorted %s carved files from %s" % (n_carved, name))

    def _extract_range_to_bin(self, lf, file_offset, byte_len, bin_path):
        """Read one range from the LayoutFile in chunks and write it to a .bin,
        computing MD5 and SHA-256 in the same pass. Returns (md5_hex, sha256)."""
        md5 = MessageDigest.getInstance("MD5")
        sha256 = MessageDigest.getInstance("SHA-256")
        buf = jarray.zeros(READ_CHUNK_SIZE, "b")
        out = FileOutputStream(File(bin_path))
        remaining = long(byte_len)
        local_off = long(file_offset)
        try:
            while remaining > 0:
                if self.context.dataSourceIngestIsCancelled():
                    break
                to_read = READ_CHUNK_SIZE
                if remaining < READ_CHUNK_SIZE:
                    to_read = int(remaining)
                # LayoutFile.read(byte[] buf, long offset, long len) -> int read.
                # TODO: verify exact signature against installed TSK build;
                # fallback would be Content.read with the same arguments.
                nread = lf.read(buf, local_off, to_read)
                if nread <= 0:
                    self.log(Level.WARNING,
                             "Short read at offset=%s (got %s); stopping run." %
                             (local_off, nread))
                    break
                out.write(buf, 0, nread)
                md5.update(buf, 0, nread)
                sha256.update(buf, 0, nread)
                local_off = local_off + nread
                remaining = remaining - nread
        finally:
            out.close()
        return (self._hex(md5.digest()), self._hex(sha256.digest()))

    def _run_photorec(self, bin_path, recup_prefix):
        """Invoke photorec_win.exe on one bin via ProcessBuilder + ExecUtil so
        Autopsy can kill it on cancellation."""
        photorec = self.local_settings.getPhotorecPath()
        cmd = self.local_settings.getPhotorecCmd()
        # photorec_win.exe /log /d <recup_prefix> /cmd "<bin>" <cmd>
        args = [photorec, "/log", "/d", recup_prefix, "/cmd", bin_path, cmd]
        self.log(Level.INFO, "Running PhotoRec: %s" % (" ".join(args),))
        pb = ProcessBuilder(args)
        # Run with cwd = the bin's work dir so photorec.log lands there.
        pb.directory(File(os.path.dirname(recup_prefix)))
        pb.redirectErrorStream(True)
        # ExecUtil.execute(ProcessBuilder, ProcessTerminator) -> int exit code.
        # DataSourceIngestModuleProcessTerminator(context) (from the .ingest
        # package) ties process lifetime to data-source ingest cancellation.
        terminator = DataSourceIngestModuleProcessTerminator(self.context)
        return ExecUtil.execute(pb, terminator)

    def _preserve_photorec_log(self, bin_work, logs_dir, bin_base):
        """Copy the photorec.log produced for a bin into a per-bin logs file so
        every log is preserved even after work dirs are sorted/cleaned."""
        src = os.path.join(bin_work, "photorec.log")
        if os.path.exists(src):
            dst = os.path.join(logs_dir, "%s.photorec.log" % (bin_base,))
            try:
                Files.copy(Paths.get(src), Paths.get(dst),
                           StandardCopyOption.REPLACE_EXISTING)
            except Exception:
                self.log(Level.WARNING,
                         "Could not preserve photorec.log for %s" % (bin_base,))

    def _sort_carved_output(self, bin_work, carved_dir, bin_base, source_bin,
                            lf, manifest_rows):
        """Walk PhotoRec's recup_dir.N output, classify each carved file by
        MIME, move it into carved/<mime_folder>/, hash it, and append a
        manifest row. Returns the count of carved files processed."""
        count = 0
        # PhotoRec creates <recup_prefix>.1, .2, ... i.e. recup_dir.N here.
        for entry in self._list_dir(bin_work):
            full = os.path.join(bin_work, entry)
            if not os.path.isdir(full):
                continue
            if not entry.startswith("recup_dir"):
                continue
            for root, dirs, files in os.walk(full):
                for fname in files:
                    if is_photorec_artifact(fname):
                        continue
                    src = os.path.join(root, fname)
                    try:
                        mime = self.detect_mime_for_path(src)
                        folder = mime_to_folder(mime)
                        dest_dir = os.path.join(carved_dir, folder)
                        self._ensure_dir(dest_dir)
                        out_name = carved_output_name(bin_base, fname)
                        dest = os.path.join(dest_dir, out_name)
                        Files.move(Paths.get(src), Paths.get(dest),
                                   StandardCopyOption.REPLACE_EXISTING)
                        sha256_hex = self._hash_file(dest, "SHA-256")
                        md5_hex = self._hash_file(dest, "MD5")
                        self.log(Level.INFO,
                                 "Carved %s mime=%s md5=%s sha256=%s" %
                                 (out_name, mime, md5_hex, sha256_hex))
                        manifest_rows.append(
                            [source_bin, dest, mime, sha256_hex])
                        count = count + 1
                        if self.local_settings.getAddDerivedFiles():
                            self._maybe_add_derived(dest, out_name, lf)
                    except Exception:
                        self.log(Level.WARNING,
                                 "Failed sorting carved file %s: %s" %
                                 (src, traceback.format_exc()))
        return count

    # ----- MIME detection --------------------------------------------------
    def detect_mime_for_path(self, path):
        """MIME type for an on-disk carved file.

        Autopsy's FileTypeDetector operates on AbstractFile objects, not on a
        path on disk, so it is not directly usable until/unless the carved file
        is added back to the case as a derived file. We therefore use
        java.nio.file.Files.probeContentType and fall back to
        application/octet-stream. (FileTypeDetector wiring is left as an
        optional enhancement for the derived-file path.)"""
        try:
            mime = Files.probeContentType(Paths.get(path))
            if mime:
                return mime
        except Exception:
            pass
        # As a secondary hint, use the signature-based extension PhotoRec gave.
        ext = os.path.splitext(path)[1].lower().lstrip(".")
        guess = EXT_MIME_HINTS.get(ext)
        if guess:
            return guess
        return DEFAULT_MIME

    # ----- derived files (optional) ----------------------------------------
    def _maybe_add_derived(self, local_path, name, parent_lf):
        """Optionally register a carved file as a derived file in the case.

        The addDerivedFile signature is long; we wrap it defensively so a
        failure here never breaks the job."""
        try:
            fm = Case.getCurrentCase().getServices().getFileManager()
            size = os.path.getsize(local_path)
            # TODO: verify FileManager.addDerivedFile(...) signature for the
            # installed Autopsy build. Timestamps are recovery-time only and
            # therefore set to 0 (untrustworthy by definition for carved data).
            fm.addDerivedFile(
                name,                       # fileName
                local_path,                 # localPath (absolute)
                long(size),                 # size
                long(0), long(0), long(0), long(0),  # ctime,crtime,atime,mtime
                True,                       # isFile
                parent_lf,                  # parentFile (the unalloc LayoutFile)
                "",                         # rederiveDetails
                MODULE_NAME,                # toolName
                MODULE_VERSION,             # toolVersion
                "Carved from APFS pool-level unallocated space by PhotoRec",
                TskData.EncodingType.NONE)  # encodingType
        except Exception:
            self.log(Level.WARNING,
                     "addDerivedFile failed for %s: %s" %
                     (name, traceback.format_exc()))

    # ----- discovery -------------------------------------------------------
    def _collect_unalloc_layout_files(self, content, out_list):
        """Recursively gather children whose type == UNALLOC_BLOCKS. For APFS
        these hang off the synthetic pool-level 'Unallocated' volume."""
        try:
            children = content.getChildren()
        except Exception:
            self.log(Level.WARNING,
                     "getChildren failed during discovery: %s" %
                     (traceback.format_exc(),))
            return
        unalloc_type = TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS
        for child in children:
            try:
                ctype = None
                if hasattr(child, "getType"):
                    ctype = child.getType()
                if ctype == unalloc_type:
                    out_list.append(child)
                    # Do not recurse into the layout file itself.
                    continue
            except Exception:
                # Some Content types have no getType(); just recurse.
                pass
            self._collect_unalloc_layout_files(child, out_list)

    # ----- directory + IO helpers -----------------------------------------
    def _prepare_dirs(self, dataSource):
        module_dir = Case.getCurrentCase().getModuleDirectory()
        root = os.path.join(module_dir, "APFS_Unalloc_PhotoRec_Carver")
        ds_label = self._data_source_label(dataSource)
        ds_dir = os.path.join(root, ds_label)
        bins_dir = os.path.join(ds_dir, "bins")
        carved_dir = os.path.join(ds_dir, "carved")
        work_dir = os.path.join(ds_dir, "work")
        logs_dir = os.path.join(ds_dir, "photorec_logs")
        for d in (root, ds_dir, bins_dir, carved_dir, work_dir, logs_dir):
            self._ensure_dir(d)
        return ds_dir, bins_dir, carved_dir, work_dir, logs_dir

    def _data_source_label(self, dataSource):
        try:
            name = dataSource.getName()
        except Exception:
            name = "datasource"
        try:
            ds_id = dataSource.getId()
        except Exception:
            ds_id = 0
        safe = "".join((c if (c.isalnum() or c in ("_", "-", ".")) else "_")
                       for c in str(name))
        return "%s_%s" % (safe, ds_id)

    def _ensure_dir(self, path):
        if not os.path.isdir(path):
            try:
                os.makedirs(path)
            except OSError:
                if not os.path.isdir(path):
                    raise

    def _list_dir(self, path):
        try:
            return os.listdir(path)
        except OSError:
            return []

    def _hash_file(self, path, algo):
        digest = MessageDigest.getInstance(algo)
        buf = jarray.zeros(READ_CHUNK_SIZE, "b")
        stream = FileInputStream(File(path))
        try:
            while True:
                nread = stream.read(buf)
                if nread <= 0:
                    break
                digest.update(buf, 0, nread)
        finally:
            stream.close()
        return self._hex(digest.digest())

    def _hex(self, byte_array):
        # byte_array is a Java signed-byte array; format unsigned hex.
        return "".join("%02x" % (b & 0xFF) for b in byte_array)

    def _write_manifest(self, path, rows):
        # csv is available in Jython 2.7.
        f = open(path, "wb")
        try:
            writer = csv.writer(f)
            writer.writerow(manifest_header())
            for row in rows:
                writer.writerow([self._csv_cell(c) for c in row])
        finally:
            f.close()

    def _csv_cell(self, value):
        if value is None:
            return ""
        if isinstance(value, unicode):
            return value.encode("utf-8")
        return str(value)

    def _write_report(self, path, dataSource, bins_written, carved_total,
                      manifest_path):
        try:
            ds_name = dataSource.getName()
        except Exception:
            ds_name = "(unknown)"
        html = []
        html.append("<html><head><meta charset='utf-8'>")
        html.append("<title>APFS Unallocated PhotoRec Carve Report</title>")
        html.append("</head><body>")
        html.append("<h1>APFS Unallocated PhotoRec Carve Report</h1>")
        html.append("<h2>Important caveats</h2>")
        html.append("<ul>")
        html.append("<li><b>The unallocated set is CONTAINER / POOL-LEVEL, "
                    "not per-volume.</b> APFS frees blocks at the container "
                    "level and The Sleuth Kit attaches unallocated runs to a "
                    "synthetic pool-level 'Unallocated' volume. The volume "
                    "selected in settings is a label/context only and did NOT "
                    "scope this carving.</li>")
        html.append("<li><b>Carved-file timestamps are recovery-time and are "
                    "NOT trustworthy.</b> Carving recovers content by signature "
                    "from free space; original filesystem metadata "
                    "(MAC times, names, paths) is not available.</li>")
        html.append("<li>The input image was treated as read-only. All output "
                    "was written under the case module directory only.</li>")
        html.append("</ul>")
        html.append("<h2>Summary</h2>")
        html.append("<table border='1' cellpadding='4'>")
        html.append("<tr><td>Data source</td><td>%s</td></tr>" %
                    (self._html(ds_name),))
        html.append("<tr><td>Module</td><td>%s %s</td></tr>" %
                    (MODULE_NAME, MODULE_VERSION))
        html.append("<tr><td>Bins (contiguous unallocated runs) written</td>"
                    "<td>%s</td></tr>" % (bins_written,))
        html.append("<tr><td>Carved files</td><td>%s</td></tr>" %
                    (carved_total,))
        html.append("<tr><td>Manifest (CSV)</td><td>%s</td></tr>" %
                    (self._html(manifest_path),))
        html.append("</table>")
        html.append("<p>Carved files are organized under <code>carved/&lt;mime&gt;"
                    "</code> folders. Every PhotoRec log is preserved under "
                    "<code>photorec_logs/</code>. SHA-256 and MD5 were computed "
                    "for every bin and every carved file.</p>")
        html.append("</body></html>")
        f = open(path, "wb")
        try:
            f.write(("\n".join(html)).encode("utf-8"))
        finally:
            f.close()

    def _html(self, value):
        s = str(value)
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;"))

    # ----- misc helpers ----------------------------------------------------
    def _post(self, msg_type, subject, detail):
        try:
            # IngestMessage.createMessage(MessageType, source, subject).
            # TODO: verify; some builds also accept a 4th details argument.
            self.services.postMessage(
                IngestMessage.createMessage(msg_type, MODULE_NAME,
                                            "%s: %s" % (subject, detail)))
        except Exception:
            self.log(Level.WARNING,
                     "postMessage failed: %s" % (traceback.format_exc(),))

    def _safe_id(self, content):
        try:
            return content.getId()
        except Exception:
            return "?"

    def _safe_seq(self, rng):
        try:
            return rng.getSequence()
        except Exception:
            return "?"


# Minimal extension->MIME hints used only as a secondary fallback when
# Files.probeContentType returns null. PhotoRec assigns signature-based
# extensions, so these are usually correct.
EXT_MIME_HINTS = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "bmp": "image/bmp", "tif": "image/tiff",
    "tiff": "image/tiff", "pdf": "application/pdf", "zip": "application/zip",
    "gz": "application/gzip", "doc": "application/msword",
    "docx": ("application/vnd.openxmlformats-officedocument."
             "wordprocessingml.document"),
    "xls": "application/vnd.ms-excel",
    "xlsx": ("application/vnd.openxmlformats-officedocument."
             "spreadsheetml.sheet"),
    "txt": "text/plain", "html": "text/html", "htm": "text/html",
    "xml": "application/xml", "mov": "video/quicktime", "mp4": "video/mp4",
    "avi": "video/x-msvideo", "mp3": "audio/mpeg", "wav": "audio/x-wav",
    "sqlite": "application/x-sqlite3", "db": "application/x-sqlite3",
}
