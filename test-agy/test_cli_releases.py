#!/usr/bin/env python3
"""Совместимость agy-гейтов патчера с официальными билдами Antigravity CLI.

Скачивает ВСЕ архивы последнего релиза
https://github.com/google-antigravity/antigravity-cli/releases
(или тега из AGY_RELEASE_TAG), распаковывает CLI-бинари (antigravity[.exe])
и проверяет:
  1. сигнатуры патчера находятся (статус не "unknown");
  2. свежий официальный бинарь имеет статус "unpatched";
  3. полный цикл patch -> "patched" -> restore -> "unpatched" на временной
     копии (скачанные оригиналы не модифицируются).

Только стандартная библиотека Python.

Запуск из корня репозитория:
    python test-agy/test_cli_releases.py
    python -m unittest discover -s test-agy -v

Переменные окружения:
    AGY_RELEASE_TAG - проверить конкретный тег вместо latest (например 1.2.7)
    AGY_TEST_CACHE  - каталог для кэширования скачанных архивов между запусками
    GITHUB_TOKEN    - токен для повышения лимита GitHub API (при rate limit)
"""
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile

REPO = "google-antigravity/antigravity-cli"
API_BASE = "https://api.github.com/repos/%s/releases" % REPO
RELEASES_PAGE = "https://github.com/%s/releases" % REPO
# Имена CLI-бинаря в архивах (официальные архивы содержат `antigravity[.exe]`,
# установленные копии/расширение VS Code также используют `agy[.exe]`).
BINARY_NAMES = ("agy", "agy.exe", "antigravity", "antigravity.exe")
USER_AGENT = "open-antigravity-patcher-compat-test"
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".zip")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "source"))

from patcher.agy import patcher as agy  # noqa: E402
from patcher.utils.atomic import apply_patches_to_data  # noqa: E402


def _request_json(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def _download(url, dest, expected_size=None, attempts=3):
    """Скачать файл с повторами при сетевых сбоях."""
    error = None
    for _ in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as f:
                shutil.copyfileobj(resp, f, length=1024 * 1024)
            if expected_size and os.path.getsize(dest) != expected_size:
                raise IOError("size mismatch: got %d, expected %d"
                              % (os.path.getsize(dest), expected_size))
            return
        except Exception as e:  # noqa: BLE001 - retry loop, error re-raised below
            error = e
            try:
                os.unlink(dest)
            except OSError:
                pass
    raise error


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_within(base, target):
    base = os.path.normcase(os.path.abspath(base)) + os.sep
    return os.path.normcase(os.path.abspath(target)).startswith(base)


def _safe_extract_tar(archive, dest):
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            if not _is_within(dest, os.path.join(dest, member.name)):
                raise IOError("unsafe path in archive: %r" % member.name)
        try:
            tf.extractall(dest, filter="data")
        except TypeError:
            tf.extractall(dest)  # Python < 3.12 без параметра filter


def _safe_extract_zip(archive, dest):
    with zipfile.ZipFile(archive) as zf:
        for name in zf.namelist():
            if not _is_within(dest, os.path.join(dest, name)):
                raise IOError("unsafe path in archive: %r" % name)
        zf.extractall(dest)


def _find_agy_binaries(root):
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name in BINARY_NAMES:
                path = os.path.join(dirpath, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    found.append(path)
    return sorted(found)


class CliReleaseCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        tag = os.environ.get("AGY_RELEASE_TAG")
        api_url = "%s/tags/%s" % (API_BASE, tag) if tag else "%s/latest" % API_BASE
        try:
            release = _request_json(api_url)
        except (urllib.error.URLError, OSError) as e:
            raise unittest.SkipTest("no network access to GitHub API: %s" % e)

        cls.tag = release.get("tag_name", "?")
        assets = [a for a in release.get("assets", [])
                  if a.get("name", "").endswith(ARCHIVE_SUFFIXES)
                  and a.get("state") == "uploaded"]
        if not assets:
            raise unittest.SkipTest("release %s has no CLI archives" % cls.tag)

        cache_dir = os.environ.get("AGY_TEST_CACHE")
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
            cls.workdir = cache_dir
            cls._cleanup = False
        else:
            cls.workdir = tempfile.mkdtemp(prefix="agy-release-test-")
            cls._cleanup = True

        print("\nRelease: %s (%d archives)" % (cls.tag, len(assets)))
        cls.cases = []     # [(asset_name, binary_path)]
        cls.problems = []  # [asset_name without agy binary]
        try:
            for asset in assets:
                cls._fetch_asset(release, asset)
        except (urllib.error.URLError, OSError) as e:
            raise unittest.SkipTest("network error while downloading: %s" % e)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "_cleanup", False):
            shutil.rmtree(cls.workdir, ignore_errors=True)
        super().tearDownClass()

    @classmethod
    def _fetch_asset(cls, release, asset):
        name = asset["name"]
        url = asset["browser_download_url"]
        size = asset.get("size")
        digest = (asset.get("digest") or "")
        archive = os.path.join(cls.workdir, "%s__%s" % (cls.tag, name))

        if os.path.isfile(archive) and size and os.path.getsize(archive) == size:
            print("  cached %s (%.1f MB)" % (name, size / 1024 / 1024))
        else:
            print("  downloading %s (%.1f MB)..." % (name, (size or 0) / 1024 / 1024))
            _download(url, archive, expected_size=size or None)

        if digest.startswith("sha256:") and _sha256(archive) != digest[7:]:
            raise IOError("sha256 mismatch for %s (see %s)" % (name, RELEASES_PAGE))

        dest = os.path.join(cls.workdir, "%s__%s extracted" % (cls.tag, name))
        if not os.path.isdir(dest):
            os.makedirs(dest, exist_ok=True)
            if name.endswith(".zip"):
                _safe_extract_zip(archive, dest)
            else:
                _safe_extract_tar(archive, dest)

        binaries = _find_agy_binaries(dest)
        if not binaries:
            cls.problems.append(name)
        for path in binaries:
            print("  found %s -> %s (%.1f MB)"
                  % (name, os.path.basename(path), os.path.getsize(path) / 1024 / 1024))
            cls.cases.append((name, path))

    def test_all_archives_contain_agy_binary(self):
        self.assertTrue(self.cases, "no CLI binaries %s found in release %s"
                        % (BINARY_NAMES, self.tag))
        self.assertEqual(self.problems, [],
                         "archives without CLI binary: %s" % self.problems)

    def test_signatures_known_and_unpatched(self):
        """Каждый официальный бинарь детектится гейтами как unpatched."""
        for asset, path in self.cases:
            with self.subTest(asset=asset):
                status, _gate = agy.get_status(path)
                self.assertNotEqual(
                    status, "unknown",
                    "gate signature not found in %s (release %s unsupported?) - %s"
                    % (asset, self.tag, RELEASES_PAGE))
                self.assertEqual(
                    status, "unpatched",
                    "expected fresh 'unpatched' binary in %s, got %r" % (asset, status))

    def test_patch_roundtrip_on_copies(self):
        """Patch -> patched -> restore -> unpatched на временных копиях."""
        for asset, path in self.cases:
            with self.subTest(asset=asset):
                with open(path, "rb") as f:
                    original = f.read()

                with tempfile.NamedTemporaryFile(prefix="agy-copy-", delete=False) as tmp:
                    copy_path = tmp.name
                try:
                    with open(copy_path, "wb") as f:
                        f.write(original)

                    # Применяем все гейты так же, как do_patch_agy.
                    patches = []
                    data = bytearray(original)
                    for gate_obj, label in agy.ALL_GATES:
                        matches = gate_obj.resolve_all(data)
                        self.assertTrue(
                            matches, "%s: no gate matched fresh %s" % (asset, asset))
                        for kind, offsets, gate in matches:
                            with self.subTest(asset=asset, gate=gate.desc):
                                self.assertEqual(
                                    kind, "unpatched",
                                    "%s: gate %r already patched in fresh %s"
                                    % (asset, gate.desc, asset))
                            for off in offsets:
                                patches.append((off, gate))
                    self.assertTrue(patches, "no patches collected for %s" % asset)

                    patched = apply_patches_to_data(bytearray(original), patches)
                    self.assertEqual(len(patched), len(original),
                                     "patch changed file size for %s" % asset)
                    with open(copy_path, "wb") as f:
                        f.write(patched)
                    self.assertEqual(
                        agy.get_status(copy_path)[0], "patched",
                        "patched binary not detected for %s" % asset)

                    # Откат побайтово в оригинал.
                    with open(copy_path, "wb") as f:
                        f.write(original)
                    with open(copy_path, "rb") as f:
                        self.assertEqual(f.read(), original)
                    self.assertEqual(
                        agy.get_status(copy_path)[0], "unpatched",
                        "restored binary not detected as unpatched for %s" % asset)
                finally:
                    if os.path.exists(copy_path):
                        os.unlink(copy_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
