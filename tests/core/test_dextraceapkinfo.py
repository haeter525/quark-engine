# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

"""
Unit and integration tests for DexTraceImp in quark/core/dextraceapkinfo.py.

Tests cover bugs that were fixed:
  1. _normalize_class did not handle the case where input starts with "L" but
     lacks a trailing ";" — it would produce a double-"L" prefix.
  2. find_method used raw == equality against DexTrace-normalized class names,
     so class names from rule files (which lack the trailing ";") returned empty
     lists.
  3. APKs with bogus ZIP compression types (e.g. 8744) caused DexTrace to
     return 0% confidence on all rules: DexTraceImp must detect the patching
     done by ApkPatcher and forward a patched temp file to DexTrace APIs so
     DexTrace reads the corrected bytes.
"""

import os
import zipfile

import pytest

try:
    from quark.core.dextraceapkinfo import DexTraceImp

    _HAS_DEXTRACE = True
except ImportError:
    _HAS_DEXTRACE = False

pytestmark = pytest.mark.skipif(
    not _HAS_DEXTRACE, reason="DexTrace not installed"
)


@pytest.fixture(scope="module")
def dextrace_instance(SAMPLE_PATH_Ahmyth):
    """Return a DexTraceImp instance backed by the Ahmyth APK."""
    return DexTraceImp(SAMPLE_PATH_Ahmyth)


# ---------------------------------------------------------------------------
# Integration tests for find_method with class names lacking trailing ";"
# ---------------------------------------------------------------------------


class TestFindMethodClassNormalization:
    """
    Regression tests verifying that find_method accepts class names both with
    and without a trailing semicolon and returns the same non-empty result.

    SmsManager.sendTextMessage is called by Ahmyth for SMS exfiltration, so it
    is reliably present in the Ahmyth call graph.
    """

    def test_find_method_with_canonical_class_name(self, dextrace_instance):
        """Fully-qualified Dalvik class name (with semicolon) returns results."""
        results = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager;", "sendTextMessage", None
        )
        assert results, (
            "find_method returned empty list for canonical class name "
            "'Landroid/telephony/SmsManager;'"
        )

    def test_find_method_without_trailing_semicolon_matches(
        self, dextrace_instance
    ):
        """Bug regression: class name without trailing semicolon returns same
        non-empty result as the canonical form."""
        with_semicolon = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager;", "sendTextMessage", None
        )
        # Clear LRU cache so the two calls are independent (different args).
        dextrace_instance.find_method.cache_clear()
        without_semicolon = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager", "sendTextMessage", None
        )
        assert without_semicolon, (
            "find_method returned empty list when class name lacks trailing ';' "
            "— regression of the _normalize_class / find_method bug"
        )
        assert set(with_semicolon) == set(without_semicolon), (
            "find_method returns different results depending on whether the "
            "trailing ';' is present"
        )

    def test_find_method_slash_separated_without_l_prefix_matches(
        self, dextrace_instance
    ):
        """Bug regression: slash-separated class name without L prefix returns
        same non-empty result as the canonical form."""
        canonical = dextrace_instance.find_method(
            "Landroid/telephony/SmsManager;", "sendTextMessage", None
        )
        dextrace_instance.find_method.cache_clear()
        slash_only = dextrace_instance.find_method(
            "android/telephony/SmsManager", "sendTextMessage", None
        )
        assert slash_only, (
            "find_method returned empty list for slash-separated class name "
            "without L prefix"
        )
        assert set(canonical) == set(slash_only)


# ---------------------------------------------------------------------------
# Bogus ZIP compression anti-analysis fix (3d52b APK)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dextrace_3d52b(SAMPLE_PATH_3d52b):
    """DexTraceImp backed by the APK that uses a bogus compression type (8744)
    on AndroidManifest.xml as an anti-analysis trick."""
    return DexTraceImp(SAMPLE_PATH_3d52b)


@pytest.mark.skipif(not _HAS_DEXTRACE, reason="DexTrace not installed")
class TestBogusCompressionFix:
    """Regression tests for the bogus ZIP compression / permissions fix.

    The 3d52b APK sets AndroidManifest.xml's compression type to 8744 while
    storing data uncompressed.  Before the fix this caused 0% confidence on
    all Quark rules because permissions came back empty (Level 1 failure).
    """

    def test_apk_is_detected_as_patched(self, dextrace_3d52b):
        """ApkPatcher must recognise the bogus compression and set isPatched."""
        assert dextrace_3d52b.isPatched is True

    def test_permissions_non_empty(self, dextrace_3d52b):
        """After the fix, permissions must be non-empty (Level 1 passes)."""
        perms = dextrace_3d52b.permissions
        assert len(perms) > 0, (
            "permissions is empty — Level 1 will fail for all rules "
            "(regression of bogus-compression fix)"
        )

    def test_permissions_include_expected(self, dextrace_3d52b):
        """INTERNET permission must be present (known from manual inspection)."""
        assert "android.permission.INTERNET" in dextrace_3d52b.permissions

    def test_no_temp_file_leak_after_gc(self, SAMPLE_PATH_3d52b):
        """DexTraceImp must not leave temp APK files on disk after the instance is GC'd."""
        import glob
        import tempfile
        tmp_dir = tempfile.gettempdir()
        apk_before = set(glob.glob(os.path.join(tmp_dir, "*.apk")))
        instance = DexTraceImp(SAMPLE_PATH_3d52b)
        del instance
        apk_after = set(glob.glob(os.path.join(tmp_dir, "*.apk")))
        assert not (apk_after - apk_before), (
            "DexTraceImp leaked temp APK files after __del__: "
            f"{apk_after - apk_before}"
        )


# ---------------------------------------------------------------------------
# Manifest fast-fail: DexTraceImp must raise ValueError on broken manifests
# ---------------------------------------------------------------------------


class TestManifestFastFail:
    """
    Regression tests for Issue 4 (broken manifest fast-fail).

    trickmo/tanglebot APKs have unreadable AndroidManifest.xml entries.
    Before the fix, DexTraceImp silently swallowed the parse error and ran
    3 full DEX passes (134 s on trickmo).  After the fix it raises ValueError
    immediately, matching Androguard's behavior.
    """

    @pytest.mark.parametrize("include_manifest,manifest_content", [
        (True, b"not-valid-axml-bytes"),   # bad AXML bytes
        (False, None),                      # missing manifest entry
    ])
    def test_unreadable_manifest_raises_value_error(
        self, tmp_path, include_manifest, manifest_content
    ):
        """APK with bad or absent AndroidManifest.xml raises ValueError."""
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            if include_manifest:
                zf.writestr("AndroidManifest.xml", manifest_content)
            zf.writestr("classes.dex", b"")
        with pytest.raises(ValueError, match="AndroidManifest"):
            DexTraceImp(str(apk_path))
