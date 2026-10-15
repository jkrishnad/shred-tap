// The live feed: one websocket to NATS, one subscription to shred.public.
// Every message is the JSON shredtap publishes, a slot summary or a rollup of the last minute.
// On connect the page also reads the latest history snapshot once, so it opens full, not empty.
import { wsconnect, type NatsConnection } from "@nats-io/nats-core";

export type Summary = {
  kind: "summary";
  slot: number;
  /** base58, null until the node has a leader schedule */
  leader: string | null;
  first_shred_ns: number;
  /** when the last batch decoded, null if nothing did */
  done_ns: number | null;
  txs: number;
  /** data shreds that never arrived, rebuilt from backup shreds */
  data_missing: number;
  /** all the slot's data shreds, 32 per FEC set, null when the slot never completed */
  data_shreds?: number | null;
  /** the slot's first shred to its first decoded transaction, from this node's view */
  first_tx_ms?: number | null;
  end: "complete" | "given_up" | "end_of_input";
  /** whether the finalization in the footer took one round, null without one */
  fast_final: boolean | null;
  sample: { sig: string; rebuilt: boolean }[];
};

export type Stats = {
  kind: "stats";
  at_ns: number;
  window_s: number;
  packets_per_s: number;
  kernel_drops: number | null;
  slots_closed: number;
  slots_given_up: number;
  slots_never_came: number;
  data_shreds_missing_pct: number;
  set_fill_ms: { p50: number; p99: number } | null;
  /** the same over only the last 5 s of sets, null percentiles when there were none */
  set_fill_ms_5s?: { p50: number | null; p99: number | null; n: number };
  /** first shred to first decoded transaction, over complete slots in the window */
  first_tx_ms?: { p50: number; p99: number } | null;
  txs_rebuilt_pct: number;
  bad_proof: number;
  bad_signature: number;
  stale_shreds?: number;
  events_dropped: number | null;
  publish_lag_ms: number | null;
};

/** The last 120 slots, ten minutes of rollups and the newest samples, refreshed every 5 s on the node. */
export type History = {
  kind: "history";
  slots: Summary[];
  stats: Stats[];
  samples: { sig: string; rebuilt: boolean; slot: number }[];
};

export type Message = Summary | Stats | History;
export type Connection = "connecting" | "live" | "reconnecting" | "closed";

/** wss://<node>/feed in production, ws://localhost:4280 through an SSH tunnel while developing */
export const FEED_URL =
  process.env.NEXT_PUBLIC_FEED_URL ?? "ws://localhost:4280";

/** A JetStream direct get of the one message on shred.history, all the public user may ask for. */
const HISTORY = "$JS.API.DIRECT.GET.SHRED_HISTORY.shred.history";

/** Connects and keeps reconnecting until stopped. Returns the stop function. */
export function connectFeed(
  onMessage: (m: Message) => void,
  onConnection: (c: Connection) => void,
): () => void {
  let nc: NatsConnection | undefined;
  let stopped = false;

  (async () => {
    try {
      nc = await wsconnect({
        servers: FEED_URL,
        // keep trying when the node or Caddy restarts, which closes every websocket
        waitOnFirstConnect: true,
        reconnect: true,
        maxReconnectAttempts: -1,
        reconnectTimeWait: 2000,
        // replies come back here, the only inbox the public user may read
        inboxPrefix: "_INBOX_public",
      });
    } catch {
      onConnection("closed");
      return;
    }
    if (stopped) {
      await nc.close();
      return;
    }
    onConnection("live");
    nc.subscribe("shred.public", {
      callback: (err, msg) => {
        if (err) return;
        try {
          onMessage(msg.json<Message>());
        } catch {
          // a message that is not JSON is skipped, the next one is fine
        }
      },
    });
    // subscribed first, so nothing is missed between the snapshot and the live messages
    void loadHistory(nc, onMessage);
    for await (const s of nc.status()) {
      if (s.type === "disconnect" || s.type === "reconnecting")
        onConnection("reconnecting");
      else if (s.type === "reconnect") {
        onConnection("live");
        // fill what was missed while disconnected
        void loadHistory(nc, onMessage);
      } else if (s.type === "close") onConnection("closed");
    }
  })();

  return () => {
    stopped = true;
    void nc?.close();
  };
}

/** Reads the snapshot once. Without one the page simply fills from the live feed. */
async function loadHistory(
  nc: NatsConnection,
  onMessage: (m: Message) => void,
) {
  try {
    const msg = await nc.request(HISTORY, new Uint8Array(), { timeout: 5000 });
    if (msg.headers?.code && msg.headers.code >= 400) return;
    onMessage(msg.json<History>());
  } catch {
    // no snapshot yet, or the node is older than this page
  }
}
