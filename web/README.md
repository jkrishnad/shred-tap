# shredtap web

The page at [shreds.vyralabs.fun](https://shreds.vyralabs.fun). It showed the shreds reaching the Vyra Labs testnet validator, slot by slot, as shredtap decoded them. The node was retired on 29 Oct 2026, so the feed is off.

![shreds.vyralabs.fun](../docs/dashboard.png)

A static Next.js export with shadcn components and Recharts. There is no server of its own: the browser connects straight to the node's NATS websocket, through Caddy at `/feed`.

## What it reads

- `shred.public`, live: one summary per closed slot and a rollup of the last minute every 5 s.
- `shred.history`, once on connect and again after a reconnect: the last 150 slots, 10 minutes of rollups and the newest sampled transactions, so the page opens full.

The public NATS user may read only these two. Every transaction, set and marker stays on the node.

## Files

- `lib/feed.ts`, the websocket connection, the message types and the history read
- `lib/use-feed.ts`, keeps the recent slots, rollups and samples, handed to React at most 4 times a second
- `app/dashboard.tsx`, the page: status pill, metric cards, slot strip, charts, integrity, recent slots and samples

## Run it

```sh
npm install
npm run dev
```

Without `NEXT_PUBLIC_FEED_URL` the page connects to `ws://localhost:4280`, the node's NATS websocket through an SSH tunnel. NATS only accepts websockets from the site's origins and `http://localhost:3000`.

`npm run build` writes the static site to `out/`. Vercel builds it with `NEXT_PUBLIC_FEED_URL=wss://node.vyralabs.fun/feed`.
