"use client";
// Keeps what the page shows: the recent slots, ten minutes of rollups and the sampled transactions.
// Messages are collected as they come and handed to React at most 4 times a second.
import { useEffect, useState } from "react";
import { connectFeed, type Connection, type Stats, type Summary } from "./feed";

export type Sample = { sig: string; rebuilt: boolean; slot: number };

export type Feed = {
  slots: Map<number, Summary>;
  maxSlot: number;
  /** the first slot this page saw, anything older was before it opened */
  firstSlot: number;
  /** oldest first, one every 5 s */
  stats: Stats[];
  /** newest first */
  samples: Sample[];
  /** when the last slot arrived, ms since the epoch */
  lastAt: number;
  connection: Connection;
};

/** Ten minutes of 5 second rollups. */
export const STATS_KEPT = 120;
const SLOTS_KEPT = 300;
const SAMPLES_KEPT = 8;

const empty = (): Feed => ({
  slots: new Map(),
  maxSlot: 0,
  firstSlot: 0,
  stats: [],
  samples: [],
  lastAt: 0,
  connection: "connecting",
});

export function useFeed(): Feed {
  const [feed, setFeed] = useState(empty);

  useEffect(() => {
    const s = empty();
    let dirty = false;
    const stop = connectFeed(
      (m) => {
        if (m.kind === "summary") {
          s.slots.set(m.slot, m);
          s.maxSlot = Math.max(s.maxSlot, m.slot);
          // the first slot seen marks when the page opened, a late straggler from before it does not move it
          if (!s.firstSlot) s.firstSlot = m.slot;
          for (const k of s.slots.keys()) if (k < s.maxSlot - SLOTS_KEPT) s.slots.delete(k);
          s.samples = [...m.sample.map((t) => ({ ...t, slot: m.slot })), ...s.samples].slice(0, SAMPLES_KEPT);
          s.lastAt = Date.now();
        } else {
          s.stats = [...s.stats, m].slice(-STATS_KEPT);
        }
        dirty = true;
      },
      (c) => {
        s.connection = c;
        dirty = true;
      },
    );
    const timer = setInterval(() => {
      if (!dirty) return;
      dirty = false;
      setFeed({ ...s, slots: new Map(s.slots) });
    }, 250);
    return () => {
      stop();
      clearInterval(timer);
    };
  }, []);

  return feed;
}
