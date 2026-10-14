#!/bin/sh
# Saves the leader schedule of this epoch and the next into one file per epoch,
# for shredtap live --leader-schedule-dir, and removes the epochs before this one.
# A file is written under a .tmp name first, so shredtap never reads half of one.
set -eu

DIR=${1:-/var/lib/shredtap/leaders}
SOLANA=${SOLANA:-solana}
CLUSTER=${SOLANA_CLUSTER:-testnet}

mkdir -p "$DIR"
epoch=$("$SOLANA" -u "$CLUSTER" epoch)

for e in "$epoch" $((epoch + 1)); do
  file="$DIR/epoch-$e.txt"
  [ -s "$file" ] && continue
  # the next epoch's schedule may not be known yet, the next run tries again
  if "$SOLANA" -u "$CLUSTER" leader-schedule --epoch "$e" > "$file.tmp" 2>/dev/null && [ -s "$file.tmp" ]; then
    mv "$file.tmp" "$file"
    echo "saved epoch $e"
  else
    rm -f "$file.tmp"
    echo "epoch $e not available yet"
  fi
done

for file in "$DIR"/epoch-*.txt; do
  [ -e "$file" ] || continue
  e=${file##*/epoch-}
  e=${e%.txt}
  if [ "$e" -lt "$epoch" ]; then
    rm -f "$file"
    echo "removed epoch $e"
  fi
done
