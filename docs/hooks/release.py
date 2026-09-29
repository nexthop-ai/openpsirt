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
carries, and the build replaces it with the version the Dockerfile pins. A
build that cannot find the pin fails, for the same reason.
"""

import os
import re
import subprocess

from mkdocs.exceptions import PluginError

# A release is vX.Y.Z, and a release candidate vX.Y.Z-rc.N. The same shapes
# the release record accepts, so nothing git describe prints for a commit
# between tags is read as one.
RELEASE = re.compile(r"^v?(\d+\.\d+\.\d+(?:-rc\.\d+)?)$")
PLACEHOLDER = re.compile(r"\{\{\s*release\s*\}\}")
SCANNER = re.compile(r"\{\{\s*scanner\s*\}\}")
# The one line in the Dockerfile that pins the scanner the image carries.
SCANNER_PIN = re.compile(r"^ARG GRYPE_VERSION=(\d+\.\d+\.\d+)\s*$", re.MULTILINE)

_release = None
_scanner = None


def _scanner_pin(root):
    path = os.path.join(root, "Dockerfile")
    try:
        with open(path, encoding="utf-8") as f:
            found = SCANNER_PIN.findall(f.read())
    except OSError as err:
        raise PluginError(f"cannot read the scanner version from {path}: {err}") from err
    if len(found) != 1:
        raise PluginError(
            f"{path} pins the scanner {len(found)} times, where the pages need exactly one"
        )
    return found[0]


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
    global _release, _scanner
    # mike hands over the configuration's path as given, relative when it
    # was, and the directory of a bare file name is empty.
    root = os.path.dirname(os.path.abspath(config.config_file_path))
    _scanner = _scanner_pin(root)
    given = os.environ.get("DOCS_RELEASE", "").strip()
    source = "DOCS_RELEASE"
    if not given:
        given = _from_git(root)
        source = "the newest release tag"
    match = RELEASE.match(given)
    if not match:
        raise PluginError(f"{source} is {given!r}, which is not a release")
    _release = match.group(1)
    return config


def on_page_markdown(markdown, page, config, files):
    return SCANNER.sub(_scanner, PLACEHOLDER.sub(_release, markdown))
