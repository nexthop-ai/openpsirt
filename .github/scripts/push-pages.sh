#!/usr/bin/env bash

# Copyright Nexthop Systems Inc.
# SPDX-License-Identifier: Apache-2.0

# Pushes the documentation pages a build bundled onto the published branch.
#
# Usage: push-pages.sh BUNDLE [REMOTE]
#
# PAGES_RERUN names what to run again when the push stops, since a release
# runs again only its documentation jobs.
#
# Only commits on top of the published branch are pushed, and never by force,
# so a build gone bad adds pages and never rewrites their history. Where the
# branch moved after the build started, or moves between the fetch and the
# push, the build's own commits are applied again on top of its new head and
# pushed again, a bounded number of times. A conflict, or a version list both
# sets changed, stops it: two sets written over each other are rebuilt, never
# merged by guess. A branch already holding the build's commits is published.
set -euo pipefail

bundle=$1
remote=${2:-origin}
branch=gh-pages
attempts=${PAGES_ATTEMPTS:-4}
rerun=${PAGES_RERUN:-re-run the workflow}
committer=(-c user.name=github-actions[bot] -c user.email=github-actions[bot]@users.noreply.github.com)

git fetch -q "$bundle" "$branch:refs/heads/built"

for ((attempt = 1; attempt <= attempts; attempt++)); do
  git fetch -q "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch" 2>/dev/null \
    || git update-ref -d "refs/remotes/$remote/$branch"
  if head=$(git rev-parse --verify -q "refs/remotes/$remote/$branch"); then
    if git merge-base --is-ancestor built "$head"; then
      # A push that landed and reported a failure, then another on top.
      exit 0
    fi
    if ! git merge-base --is-ancestor "$head" built; then
      base=$(git merge-base "$head" built) || {
        status=$?
        # git answers 1 for no common commit, and another status for a fault.
        if [ "$status" -eq 1 ]; then
          echo "the published branch shares no history with the pages built: $rerun" >&2
        else
          echo "git could not compare the published branch with the pages built: $rerun" >&2
        fi
        exit "$status"
      }
      # Both sets rewrote the version list: merged by line, it can parse and
      # still name a version twice or move an alias to two places.
      if ! git diff --quiet "$base" "$head" -- versions.json \
          && ! git diff --quiet "$base" built -- versions.json; then
        echo "the published branch moved after the pages were built, and both changed the version list: $rerun" >&2
        exit 1
      fi
      # The build's own commits: what it holds that the branch never did,
      # since the branch's history is never rewritten.
      git checkout -q --detach "$head"
      if ! git "${committer[@]}" cherry-pick --keep-redundant-commits \
          $(git rev-list --reverse built --not "$head") > /dev/null; then
        git cherry-pick --abort || true
        echo "the published branch moved after the pages were built, and they do not apply on top of it: $rerun" >&2
        exit 1
      fi
      git branch -f built HEAD
      git checkout -q --detach built
    fi
  fi
  if git push -q "$remote" "built:refs/heads/$branch"; then
    exit 0
  fi
  echo "the published branch moved while the pages were pushed; applying them again" >&2
done
echo "the published branch kept moving through $attempts pushes: $rerun" >&2
exit 1
