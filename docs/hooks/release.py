# Copyright Nexthop Systems Inc.
# SPDX-License-Identifier: Apache-2.0

"""The release a documentation build describes, written into its pages.

A page writes {{ release }} wherever it names the release a reader deploys,
and the build replaces it with a version such as 0.4.0. The version is read
from DOCS_RELEASE when that is set, which is how both workflows pass it, and
otherwise from the newest release tag reachable from the checkout. A build
that can resolve neither fails: a page naming no version, or a default one,
tells somebody to deploy something that is not a release.

A page writes {{ scanner }} wherever it names the scanner version the image
carries, and {{ scanner_sha256_amd64 }} and {{ scanner_sha256_arm64 }} for the
checksums the image build verifies its download against. The build replaces
each with what the Dockerfile pins, and fails where it cannot find the pin.

PLACEHOLDERS is every name a page may write. The build fails on a page writing
any other, and on a name here that nothing fills, so a placeholder is never
published as written. A test of the pages reads this list.
"""

import os
import re
import subprocess

from mkdocs.exceptions import PluginError

PLACEHOLDERS = ("release", "scanner", "scanner_sha256_amd64", "scanner_sha256_arm64")

# A release is vX.Y.Z, and a release candidate vX.Y.Z-rc.N. The same shapes
# the release record accepts, so nothing git describe prints for a commit
# between tags is read as one.
RELEASE = re.compile(r"^v?(\d+\.\d+\.\d+(?:-rc\.\d+)?)$")
# A name in double braces. A workflow expression, ${{ matrix.variant }}, in a
# pipeline example is not one: it follows a dollar sign and holds a dot.
PLACEHOLDER = re.compile(r"(?<!\$)\{\{\s*([a-z0-9_]+)\s*\}\}")
# The one line in the Dockerfile that pins the scanner the image carries, and
# the checksum it verifies the download against for each architecture.
SCANNER_PIN = re.compile(r"^ARG GRYPE_VERSION=(\d+\.\d+\.\d+)\s*$", re.MULTILINE)
SCANNER_SUM = re.compile(r"^\s*(amd64|arm64)\) expected=([0-9a-f]{64}) ;;", re.MULTILINE)
# The stage that fetches the scanner. Another stage pins another tool's
# checksums the same way, so the checksums are read from this one alone.
SCANNER_STAGE = re.compile(r"^FROM \S+ AS scanner$(.*?)^FROM ", re.MULTILINE | re.DOTALL)

_filled = {}


def _one(path, found, what):
    if len(found) != 1:
        raise PluginError(f"{path} pins {what} {len(found)} times, where the pages need exactly one")
    return found[0]


def _scanner_pins(root):
    path = os.path.join(root, "Dockerfile")
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as err:
        raise PluginError(f"cannot read the scanner version from {path}: {err}") from err
    stage = SCANNER_STAGE.search(text)
    if not stage:
        raise PluginError(f"{path} has no stage named scanner")
    text = stage.group(1)
    pins = {"scanner": _one(path, SCANNER_PIN.findall(text), "the scanner")}
    for arch in ("amd64", "arm64"):
        sums = [digest for named, digest in SCANNER_SUM.findall(text) if named == arch]
        pins["scanner_sha256_" + arch] = _one(path, sums, f"the scanner's {arch} checksum")
    return pins


def _from_git(root):
    # Release candidates are excluded: the pages built from main point at the
    # release somebody is meant to be running.
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0",
             "--match", "v[0-9]*", "--exclude", "*-*"],
            cwd=root, capture_output=True, text=True, check=True,
        )
    except (OSError, subprocess.CalledProcessError) as err:
        detail = getattr(err, "stderr", "") or str(err)
        raise PluginError(
            "no release tag is reachable from this checkout, and DOCS_RELEASE "
            "is not set: " + detail.strip()
        ) from err
    return out.stdout.strip()


def on_config(config):
    global _filled
    # mike hands over the configuration's path as given, relative when it
    # was, and the directory of a bare file name is empty.
    root = os.path.dirname(os.path.abspath(config.config_file_path))
    filled = _scanner_pins(root)
    given = os.environ.get("DOCS_RELEASE", "").strip()
    source = "DOCS_RELEASE"
    if not given:
        given = _from_git(root)
        source = "the newest release tag"
    match = RELEASE.match(given)
    if not match:
        raise PluginError(f"{source} is {given!r}, which is not a release")
    filled["release"] = match.group(1)
    if sorted(filled) != sorted(PLACEHOLDERS):
        raise PluginError(f"the build fills {sorted(filled)}, and pages may write {sorted(PLACEHOLDERS)}")
    _filled = filled
    return config


def on_page_markdown(markdown, page, config, files):
    def fill(found):
        name = found.group(1)
        if name not in _filled:
            raise PluginError(f"{page.file.src_uri} writes {{{{ {name} }}}}, which the build does not fill in")
        return _filled[name]

    return PLACEHOLDER.sub(fill, markdown)
