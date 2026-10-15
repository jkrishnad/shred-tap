"use client";
// Keeps what the page shows: the recent slots, ten minutes of rollups and the sampled transactions.
// Messages are collected as they come and handed to React at most 4 times a second.
import { useEffect, useState } from "react";
import { connectFeed, type Connection, type History, type Stats, type Summary } from "./feed";

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

/** A slot as it closes, live. */
function addSummary(feed: Feed, summary: Summary) {
  feed.slots.set(summary.slot, summary);
  feed.maxSlot = Math.max(feed.maxSlot, summary.slot);
  // the first slot seen marks when the page opened, a late straggler from before it does not move it
  if (feed.firstSlot === 0) feed.firstSlot = summary.slot;

  // forget slots too old to be on screen
  for (const slot of feed.slots.keys()) {
    if (slot < feed.maxSlot - SLOTS_KEPT) feed.slots.delete(slot);
  }

  // its sampled transactions go first, the list keeps the newest few
  const fresh = summary.sample.map((t) => ({ ...t, slot: summary.slot }));
  feed.samples = [...fresh, ...feed.samples];
  feed.samples.length = Math.min(feed.samples.length, SAMPLES_KEPT);

  feed.lastAt = Date.now();
}

/** A rollup every 5 s, the newest last. */
function addStats(feed: Feed, stats: Stats) {
  feed.stats.push(stats);
  if (feed.stats.length > STATS_KEPT) feed.stats.shift();
}

/** The snapshot read on connect. It only fills in, anything that already came live is kept. */
function addHistory(feed: Feed, history: History) {
  for (const summary of history.slots) {
    if (feed.slots.has(summary.slot)) continue;
    feed.slots.set(summary.slot, summary);
    feed.maxSlot = Math.max(feed.maxSlot, summary.slot);
    // the history reaches back before the page opened, so the strip starts at its oldest slot
    if (feed.firstSlot === 0 || summary.slot < feed.firstSlot) feed.firstSlot = summary.slot;
  }

  // rollups the page has not seen yet, then everything in time order
  const seen = new Set(feed.stats.map((s) => s.at_ns));
  for (const stats of history.stats) {
    if (!seen.has(stats.at_ns)) feed.stats.push(stats);
  }
  feed.stats.sort((a, b) => a.at_ns - b.at_ns);
  while (feed.stats.length > STATS_KEPT) feed.stats.shift();

  if (feed.samples.length === 0) feed.samples = history.samples.slice(0, SAMPLES_KEPT);
  if (feed.lastAt === 0) feed.lastAt = Date.now();
}

export function useFeed(): Feed {
  const [feed, setFeed] = useState(empty);

  useEffect(() => {
    const s = empty();
    let dirty = false;
    const stop = connectFeed(
      (m) => {
        if (m.kind === "history") addHistory(s, m);
        else if (m.kind === "summary") addSummary(s, m);
        else addStats(s, m);
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
      // fresh copies, so React sees a change
      setFeed({ ...s, slots: new Map(s.slots), stats: [...s.stats], samples: [...s.samples] });
    }, 250);
    return () => {
      stop();
      clearInterval(timer);
    };
  }, []);

  return feed;
}
