// The live feed: one websocket to NATS, one subscription to shred.public.
// Every message is the JSON shredtap publishes, a slot summary or a rollup of the last minute.
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
  txs_rebuilt_pct: number;
  bad_proof: number;
  bad_signature: number;
  events_dropped: number | null;
  publish_lag_ms: number | null;
};

export type Message = Summary | Stats;
export type Connection = "connecting" | "live" | "reconnecting" | "closed";

/** wss://<node>/feed in production, ws://localhost:4280 through an SSH tunnel while developing */
export const FEED_URL = process.env.NEXT_PUBLIC_FEED_URL ?? "ws://localhost:4280";

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
    for await (const s of nc.status()) {
      if (s.type === "disconnect" || s.type === "reconnecting") onConnection("reconnecting");
      else if (s.type === "reconnect") onConnection("live");
      else if (s.type === "close") onConnection("closed");
    }
  })();

  return () => {
    stopped = true;
    void nc?.close();
  };
}
