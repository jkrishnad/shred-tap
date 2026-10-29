# shredtap web

The page at [shreds.vyralabs.fun](https://shreds.vyralabs.fun). It showed the shreds reaching the Vyra Labs testnet validator, slot by slot, as shredtap decoded them. The node was retired on 29 Oct 2026, so the feed is off.

![shredtap dashboard](../docs/dashboard.png)

A static Next.js export with shadcn components and Recharts. It has no server of its own. The browser connects straight to the NATS websocket that `shredtap live --nats` publishes to.

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

Until the feed connects, the page shows the node as offline. It keeps retrying in the background.

Without `NEXT_PUBLIC_FEED_URL` the page connects to `ws://localhost:4280`, the websocket port in `../deploy/nats.conf`. NATS only accepts websockets from the origins in its `allowed_origins`, which includes `http://localhost:3000` for `npm run dev`.

`npm run build` writes the static site to `out/`. Set `NEXT_PUBLIC_FEED_URL` at build time to your feed's `wss://` address.
