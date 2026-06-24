#!/usr/bin/env bash
set -e
ROOT=$(git rev-parse --show-toplevel)
IDX="$ROOT/.superpowers/sdd/snap.idx"
rm -f "$IDX"
GIT_INDEX_FILE="$IDX" git --work-tree="$ROOT" read-tree HEAD
GIT_INDEX_FILE="$IDX" git --work-tree="$ROOT" add -A
GIT_INDEX_FILE="$IDX" git --work-tree="$ROOT" write-tree
