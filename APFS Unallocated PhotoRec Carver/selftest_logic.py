# -*- coding: utf-8 -*-
#
# selftest_logic.py
#
# Independent check of the PURE-LOGIC helpers in
# apfs_unalloc_photorec_carver.py (range->offset math, MIME->folder mapping,
# bin naming, PhotoRec-artifact filtering, carved-name collision avoidance).
#
# The real module imports Java/Autopsy classes that only exist inside Jython,
# so it cannot be imported under plain CPython. To avoid duplicating the logic
# (and the drift that invites), this test parses the real source with `ast`,
# pulls out exactly the helper FunctionDefs by name, and exec's them in a clean
# namespace. It therefore tests the SHIPPING code, not a copy.
#
# Run with either Python 2.7 or Python 3:  python selftest_logic.py
import ast
import os

HELPERS = [
    "range_file_offsets",
    "bin_name",
    "mime_to_folder",
    "is_photorec_artifact",
    "carved_output_name",
    "manifest_header",
    "content_type_name",
    "is_structural_content",
    "build_photorec_command",
]

# Constants the helpers reference at module scope.
PRELUDE = {
    "DEFAULT_MIME": "application/octet-stream",
    "STRUCTURAL_TYPE_NAMES": ("Image", "VolumeSystem", "Volume", "Pool"),
}


def load_helpers():
    here = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(here, "apfs_unalloc_photorec_carver.py")
    f = open(src_path, "r")
    try:
        source = f.read()
    finally:
        f.close()
    tree = ast.parse(source)
    ns = dict(PRELUDE)
    wanted = set(HELPERS)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            try:
                mod = ast.Module(body=[node], type_ignores=[])
            except TypeError:
                # Python 2 ast.Module takes only the body.
                mod = ast.Module(body=[node])
            code = compile(ast.fix_missing_locations(mod),
                           filename="<helpers>", mode="exec")
            exec(code, ns)
    missing = wanted - set(ns)
    if missing:
        raise AssertionError("helpers not found in source: %s" % (missing,))
    return ns


def run():
    h = load_helpers()
    checks = 0

    def eq(actual, expected, label):
        if actual != expected:
            raise AssertionError("%s: got %r, expected %r" %
                                 (label, actual, expected))

    # range_file_offsets: running sum of prior lengths.
    eq(h["range_file_offsets"]([100, 50, 200]), [0, 100, 150], "offsets basic")
    eq(h["range_file_offsets"]([]), [], "offsets empty")
    eq(h["range_file_offsets"]([4096]), [0], "offsets single")
    eq(h["range_file_offsets"]([1, 1, 1, 1]), [0, 1, 2, 3], "offsets unit")
    # large values (APFS containers are big) must not overflow.
    big = 5 * 1024 * 1024 * 1024
    eq(h["range_file_offsets"]([big, big]), [0, big], "offsets large")
    checks += 5

    # bin_name
    eq(h["bin_name"](7, 1048576, 4096),
       "unalloc_7_off1048576_len4096.bin", "bin_name")
    checks += 1

    # mime_to_folder
    eq(h["mime_to_folder"]("image/jpeg"), "image_jpeg", "mime jpeg")
    eq(h["mime_to_folder"]("application/pdf"), "application_pdf", "mime pdf")
    eq(h["mime_to_folder"]("text/plain; charset=utf-8"),
       "text_plain", "mime params stripped")
    eq(h["mime_to_folder"](None), "application_octet-stream", "mime none")
    eq(h["mime_to_folder"](""), "application_octet-stream", "mime empty")
    eq(h["mime_to_folder"]("weirdvalue"), "weirdvalue_unknown", "mime no-slash")
    eq(h["mime_to_folder"]("image/svg+xml"), "image_svg+xml", "mime plus kept")
    eq(h["mime_to_folder"]("application/x-7z-compressed"),
       "application_x-7z-compressed", "mime dashes kept")
    # sanitization of unsafe characters.
    eq(h["mime_to_folder"]("foo/bar baz"), "foo_bar_baz", "mime space->_")
    checks += 9

    # is_photorec_artifact
    eq(h["is_photorec_artifact"]("photorec.log"), True, "artifact log")
    eq(h["is_photorec_artifact"]("report.xml"), True, "artifact report")
    eq(h["is_photorec_artifact"]("t1000000.jpg"), True, "artifact thumb")
    eq(h["is_photorec_artifact"]("f0000001.jpg"), False, "carved f-file")
    eq(h["is_photorec_artifact"]("test.png"), False, "t-word not thumb")
    checks += 5

    # carved_output_name
    eq(h["carved_output_name"]("unalloc_7_off0_len4096", "f0000001.jpg"),
       "unalloc_7_off0_len4096__f0000001.jpg", "carved name")
    checks += 1

    # manifest_header
    eq(h["manifest_header"](),
       ["source_bin", "carved_file", "mime", "sha256"], "manifest header")
    checks += 1

    # content_type_name / is_structural_content — the EDT-hang guard. These
    # mirror Jython's Java Content objects with a tiny stub exposing
    # getClass().getSimpleName(); None must degrade to "" / False, not raise.
    class _SimpleName(object):
        def __init__(self, name):
            self._name = name

        def getSimpleName(self):
            return self._name

    class _FakeContent(object):
        def __init__(self, name):
            self._sn = _SimpleName(name)

        def getClass(self):
            return self._sn

    eq(h["content_type_name"](None), "", "type name of None")
    eq(h["content_type_name"](_FakeContent("Volume")), "Volume", "type name")
    eq(h["is_structural_content"](None), False, "None not structural")
    eq(h["is_structural_content"](_FakeContent("Volume")), True, "Volume struct")
    eq(h["is_structural_content"](_FakeContent("Pool")), True, "Pool struct")
    eq(h["is_structural_content"](_FakeContent("Image")), True, "Image struct")
    eq(h["is_structural_content"](_FakeContent("VolumeSystem")), True,
       "VolumeSystem struct")
    # The crucial negatives: never recurse into these (that is the hang).
    eq(h["is_structural_content"](_FakeContent("FileSystem")), False,
       "FileSystem NOT structural")
    eq(h["is_structural_content"](_FakeContent("Directory")), False,
       "Directory NOT structural")
    eq(h["is_structural_content"](_FakeContent("File")), False,
       "File NOT structural")
    eq(h["is_structural_content"](_FakeContent("LayoutFile")), False,
       "LayoutFile NOT structural")
    checks += 11

    # build_photorec_command — default is WAV only; enables ONLY selection.
    eq(h["build_photorec_command"](["wav"]),
       "wholespace,fileopt,everything,disable,wav,enable,search", "cmd wav")
    eq(h["build_photorec_command"]([]),
       "wholespace,fileopt,everything,disable,wav,enable,search", "cmd empty->wav")
    eq(h["build_photorec_command"](None),
       "wholespace,fileopt,everything,disable,wav,enable,search", "cmd None->wav")
    eq(h["build_photorec_command"](["jpg", "png"]),
       "wholespace,fileopt,everything,disable,jpg,enable,png,enable,search",
       "cmd multi")
    # dedupe + whitespace-trim + drop empties.
    eq(h["build_photorec_command"]([" jpg ", "jpg", "", None, "png"]),
       "wholespace,fileopt,everything,disable,jpg,enable,png,enable,search",
       "cmd dedup/trim")
    # never carves "everything" implicitly.
    if "everything,enable" in h["build_photorec_command"](["wav"]):
        raise AssertionError("cmd must not enable everything by default")
    checks += 6

    print("OK - %d assertions passed across %d helpers" %
          (checks, len(HELPERS)))


if __name__ == "__main__":
    run()
