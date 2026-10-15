"use client";
// The page: shadcn cards, badges, table and charts over the live feed.
import { useEffect, useState } from "react";
import { Area, AreaChart, Bar, BarChart, Cell, XAxis, YAxis } from "recharts";
import { Badge } from "@/components/ui/badge";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Stats, Summary } from "@/lib/feed";
import { type Feed, STATS_KEPT, useFeed } from "@/lib/use-feed";

/** Provisional levels, to be set from a day of real rollups. */
const LEVELS = { loss: { warn: 2, bad: 5 }, missingSlot: 4, readyP50: 150 };
/** A slot is amber when more than this share of its data shreds was rebuilt (provisional). */
const AMBER_SHARE = 0.02;
/** The missing shreds chart is fixed to this, a taller bar is drawn capped at the top. */
const BAR_MAX = 20;

type State = "ok" | "warn" | "bad" | "none";
/** The panels that hold still while hovered. */
type Panel = "bars" | "table" | "samples";

/** Small uppercase panel titles, as in the design. */
const TITLE = "text-[11px] font-normal uppercase tracking-wider text-muted-foreground";

const states = {
  ok: { label: "complete", color: "var(--chart-3)" },
  warn: { label: "over 2% of data shreds rebuilt", color: "var(--chart-4)" },
  bad: { label: "never completed", color: "var(--chart-5)" },
  none: { label: "no shreds, skipped or ours", color: "#c9d1d6" },
} satisfies ChartConfig;

const lines = {
  p50: { label: "p50", color: "var(--chart-1)" },
  p99: { label: "p99", color: "var(--chart-2)" },
} satisfies ChartConfig;

const fmt = (n: number | null | undefined, d = 0) =>
  n == null ? "-" : n.toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d });
const short = (k: string | null | undefined) => (k ? `${k.slice(0, 4)}…${k.slice(-4)}` : "-");
const slotMs = (s: Summary) => (s.done_ns == null ? null : (s.done_ns - s.first_shred_ns) / 1e6);

function slotState(s: Summary | undefined): State {
  if (!s) return "none";
  if (s.end !== "complete") return "bad";
  // a share of the slot's own data shreds, so a big slot isn't amber just for being big
  if (s.data_shreds) return s.data_missing / s.data_shreds > AMBER_SHARE ? "warn" : "ok";
  return s.data_missing >= LEVELS.missingSlot ? "warn" : "ok";
}

/** The 120 slot numbers on screen, aligned so every group of 4 is one leader window. */
function window120(maxSlot: number) {
  const first = (Math.floor(maxSlot / 4) - 29) * 4;
  return Array.from({ length: 120 }, (_, i) => first + i).filter((s) => s <= maxSlot);
}

/** The header pill. Loss is upstream, so it names the network's state, not our node's.
 *  Only drops and invalid shreds are about this side. */
function health(s: Stats): { state: State; label: string } {
  const loss = s.data_shreds_missing_pct;
  if (s.bad_proof > 0 || s.bad_signature > 0) return { state: "bad", label: "invalid shreds" };
  if ((s.kernel_drops ?? 0) > 0 || (s.events_dropped ?? 0) > 0) return { state: "bad", label: "capture issue" };
  if (loss > LEVELS.loss.bad) return { state: "bad", label: `network overloaded · ${fmt(loss, 1)}% loss` };
  if (loss > LEVELS.loss.warn) return { state: "warn", label: `network busy · ${fmt(loss, 1)}% loss` };
  return { state: "ok", label: "healthy" };
}

export default function Dashboard() {
  const feed = useFeed();
  const last = feed.stats[feed.stats.length - 1];

  // hovering a panel holds only that panel still so it can be read, space holds the missing shreds chart.
  // The feed keeps coming underneath, and resuming jumps back to live.
  const [hovered, setHovered] = useState<Panel | null>(null);
  const [held, setHeld] = useState(false);
  const barsFrozen = useFrozen(feed, hovered === "bars" || held);
  const tableFrozen = useFrozen(feed, hovered === "table");
  const samplesFrozen = useFrozen(feed, hovered === "samples");
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.code !== "Space" || e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      e.preventDefault();
      setHeld((h) => !h);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const hover = (panel: Panel) => ({ onPointerEnter: () => setHovered(panel), onPointerLeave: () => setHovered(null) });
  const frozen = barsFrozen ?? tableFrozen ?? samplesFrozen;
  // the samples panel counts the transactions that came after the pause, the others count slots
  const newer = frozen ? [...feed.slots.values()].filter((s) => s.slot > frozen.maxSlot) : [];
  let waiting = newer.length;
  let unit = "slot";
  if (samplesFrozen) {
    waiting = 0;
    for (const s of newer) waiting += s.sample.length;
    unit = "tx";
  }
  const view = barsFrozen ?? feed;
  const tableView = tableFrozen ?? feed;
  const samples = (samplesFrozen ?? feed).samples;

  const nums = feed.maxSlot ? window120(feed.maxSlot) : [];
  const pausedNums = view.maxSlot ? window120(view.maxSlot) : [];
  // slots from before the page opened are left blank, not counted as missing,
  // and an empty bar after every leader window of 4 slots keeps the windows apart
  const strip = nums.flatMap((slot) => {
    const cell = { key: String(slot), v: slot < feed.firstSlot ? 0 : 1, state: slotState(feed.slots.get(slot)) };
    return slot % 4 === 3 && slot !== feed.maxSlot ? [cell, { key: `gap${slot}`, v: 0, state: "none" as State }] : [cell];
  });
  const bars = pausedNums.map((slot) => {
    const s = view.slots.get(slot);
    const state = slotState(s);
    // a slot that never completed is a full height red bar, the rest are capped at the top
    const missing = !s ? null : state === "bad" ? BAR_MAX : Math.min(s.data_missing, BAR_MAX);
    return { slot, missing, state, real: s?.data_missing ?? 0, total: s?.data_shreds ?? null };
  });
  const rows = [...tableView.slots.values()].sort((a, b) => b.slot - a.slot).slice(0, 14);
  // each 5 s on its own, a gap where no set filled, no smoothing across it
  const series = feed.stats.map((s, i) => ({ i, p50: s.set_fill_ms_5s?.p50 ?? null, p99: s.set_fill_ms_5s?.p99 ?? null }));
  const readyTicks = roundTicks(Math.max(0, ...series.map((p) => p.p99 ?? 0)));
  const pill =
    feed.connection !== "live"
      ? { state: "none" as State, label: feed.connection }
      : !last
        ? { state: "none" as State, label: "waiting for stats" }
        : health(last);
  const h = pill.state;

  return (
    <main className="mx-auto grid max-w-7xl gap-4 px-4 py-5">
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h1 className="text-lg font-semibold">shreds</h1>
        <span className="text-sm text-muted-foreground">Vyra Labs testnet validator · Singapore · UDP 8001</span>
        <Badge variant={h === "bad" ? "destructive" : "outline"} style={h !== "none" ? { color: states[h].color } : undefined}>
          {pill.label}
        </Badge>
        <div className="flex-1" />
        <div className="flex gap-4 text-xs text-muted-foreground">
          <span>slot <b className="font-mono text-foreground">{feed.maxSlot || "-"}</b></span>
          <span>leader <b className="font-mono text-foreground">{short(feed.slots.get(feed.maxSlot)?.leader)}</b></span>
          <span>updated <b className="font-mono text-foreground"><Age at={feed.lastAt} /></b></span>
        </div>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className={TITLE}>Last 120 slots</CardTitle>
          <CardDescription>grouped by leader window of 4 slots, newest on the right</CardDescription>
        </CardHeader>
        <CardContent>
          <ChartContainer config={states} className="aspect-auto h-10 w-full">
            <BarChart data={strip} barCategoryGap={1} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
              <Bar dataKey="v" isAnimationActive={false}>
                {strip.map((d) => (
                  <Cell
                    key={d.key}
                    fill={d.state === "none" ? "transparent" : `var(--color-${d.state})`}
                    stroke={d.state === "none" && d.v ? "var(--color-none)" : undefined}
                    fillOpacity={d.state === "ok" ? 0.55 : 1}
                  />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
          <div className="mt-2 flex flex-wrap gap-2">
            {(Object.keys(states) as State[]).map((k) => (
              <Badge key={k} variant="outline" style={{ color: states[k].color }}>{states[k].label}</Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Metric title="Packets in" value={fmt(last?.packets_per_s)} unit="pkt/s"
          note={`kernel drops ${fmt(last?.kernel_drops)}`} state={(last?.kernel_drops ?? 0) > 0 ? "warn" : "ok"}
          values={feed.stats.map((s) => s.packets_per_s)} />
        <Metric title="Data shreds missing" value={fmt(last?.data_shreds_missing_pct, 2)} unit="%"
          note="in complete slots, last minute"
          state={!last ? "ok" : last.data_shreds_missing_pct > LEVELS.loss.bad ? "bad" : last.data_shreds_missing_pct > LEVELS.loss.warn ? "warn" : "ok"}
          values={feed.stats.map((s) => s.data_shreds_missing_pct)} />
        <Metric title="Set ready p50" value={fmt(last?.set_fill_ms?.p50)} unit="ms"
          note={`p99 ${fmt(last?.set_fill_ms?.p99)} ms`} state={(last?.set_fill_ms?.p50 ?? 0) > LEVELS.readyP50 ? "warn" : "ok"}
          values={feed.stats.flatMap((s) => (s.set_fill_ms ? [s.set_fill_ms.p50] : []))} />
        <Metric title="First tx readable" value={fmt(last?.first_tx_ms?.p50)} unit="ms"
          note={`p99 ${fmt(last?.first_tx_ms?.p99)} ms after the block's first shred`} state="ok"
          values={feed.stats.flatMap((s) => (s.first_tx_ms ? [s.first_tx_ms.p50] : []))} />
        <Metric title="Transactions rebuilt" value={fmt(last?.txs_rebuilt_pct, 1)} unit="%"
          note="in a batch that needed backup shreds" state="ok" values={feed.stats.map((s) => s.txs_rebuilt_pct)} />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3" {...hover("bars")}>
          <CardHeader>
            <CardTitle className={TITLE}>Missing data shreds per slot</CardTitle>
            <CardDescription>rebuilt from backup shreds, amber over 2% of the slot, red where it never completed</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={states} className="aspect-auto h-56 w-full">
              <BarChart data={bars} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <XAxis dataKey="slot" tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={80} />
                <YAxis domain={[0, BAR_MAX]} ticks={[0, 5, 10, 15, 20]} allowDataOverflow tickLine={false} axisLine={false} />
                <ChartTooltip
                  content={
                    <ChartTooltipContent
                      hideIndicator
                      labelFormatter={(_, p) => `slot ${p?.[0]?.payload?.slot}`}
                      formatter={(_, __, item) => missingText(item.payload)}
                    />
                  }
                />
                <Bar dataKey="missing" name="missing" isAnimationActive={false}>
                  {bars.map((d) => (
                    <Cell key={d.slot} fill={`var(--color-${d.state === "ok" ? "ok" : d.state})`} />
                  ))}
                </Bar>
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className={TITLE}>Set ready time, last 10 min</CardTitle>
            <CardDescription>first shred of a set to its 32nd, in ms, each point 5 s of sets</CardDescription>
            {feed.stats.length < STATS_KEPT && (
              <CardAction className="font-mono text-xs text-muted-foreground">
                collecting · {fmt((feed.stats.length * 5) / 60, 1)} of 10 min
              </CardAction>
            )}
          </CardHeader>
          <CardContent>
            <ChartContainer config={lines} className="aspect-auto h-56 w-full">
              <AreaChart data={series} margin={{ top: 8, right: 4, bottom: 8, left: -20 }}>
                <XAxis dataKey="i" hide />
                <YAxis domain={[0, readyTicks[readyTicks.length - 1]]} ticks={readyTicks} interval={0} tickLine={false} axisLine={false} />
                <ChartTooltip content={<ChartTooltipContent hideLabel />} />
                <Area dataKey="p99" type="linear" stroke="var(--color-p99)" fill="none" isAnimationActive={false} />
                <Area dataKey="p50" type="linear" stroke="var(--color-p50)" fill="var(--color-p50)" fillOpacity={0.15} isAnimationActive={false} />
              </AreaChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3" {...hover("table")}>
          <CardHeader><CardTitle className={TITLE}>Recent slots</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Slot</TableHead>
                  <TableHead>Leader</TableHead>
                  <TableHead className="text-right">Txs</TableHead>
                  <TableHead className="text-right">Missing</TableHead>
                  <TableHead className="text-right">Slot time</TableHead>
                  <TableHead className="text-right">Final</TableHead>
                  <TableHead className="text-right">Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className="font-mono">
                {rows.map((s) => {
                  const k = slotState(s);
                  return (
                    <TableRow key={s.slot}>
                      <TableCell>{s.slot}</TableCell>
                      <TableCell>{short(s.leader)}</TableCell>
                      <TableCell className="text-right">{s.end === "complete" ? fmt(s.txs) : "-"}</TableCell>
                      <TableCell className="text-right">{s.end === "complete" ? s.data_missing : "-"}</TableCell>
                      <TableCell className="text-right">{slotMs(s) == null ? "-" : `${fmt(slotMs(s))} ms`}</TableCell>
                      <TableCell className="text-right">{s.fast_final == null ? "-" : s.fast_final ? "fast" : "slow"}</TableCell>
                      <TableCell className="text-right">
                        <Badge variant="outline" style={{ color: states[k].color }}>
                          {k === "bad" ? "never completed" : k === "warn" ? "rebuilt" : "complete"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <div className="grid content-start gap-4 lg:col-span-2">
          <Card>
            <CardHeader><CardTitle className={TITLE}>Integrity, last minute</CardTitle></CardHeader>
            <CardContent className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-2 text-sm">
              {[
                ["Bad Merkle proofs", fmt(last?.bad_proof)],
                ["Bad leader signatures", fmt(last?.bad_signature)],
                ["Slots closed", fmt(last?.slots_closed)],
                ["Slots never completed", fmt(last?.slots_given_up)],
                ["Slots with no shreds", fmt(last?.slots_never_came)],
              ].map(([k, v]) => (
                <Row key={k} k={k} v={v} />
              ))}
              <Separator className="col-span-2" />
              <Row k="Messages dropped" v={fmt(last?.events_dropped)} />
              <Row k="Publish lag" v={last?.publish_lag_ms == null ? "-" : `${fmt(last.publish_lag_ms, 2)} ms`} />
            </CardContent>
          </Card>
          <Card {...hover("samples")}>
            <CardHeader><CardTitle className={TITLE}>Sampled transactions</CardTitle></CardHeader>
            <CardContent className="grid gap-2 font-mono text-sm">
              {samples.map((t) => (
                <div key={t.sig} className="flex justify-between gap-3 border-b pb-2">
                  <a href={`https://explorer.solana.com/tx/${t.sig}?cluster=testnet`} target="_blank" rel="noopener" className="hover:underline">
                    {short(t.sig)}
                  </a>
                  <span className="text-muted-foreground">
                    {t.slot}
                    {t.rebuilt && <span style={{ color: states.warn.color }}> · rebuilt</span>}
                  </span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        A set needs any 32 of its 64 shreds, so missing data shreds are rebuilt from backup shreds. A slot with no
        shreds was skipped by its leader, or was one of ours, which never reach us inbound. Stats cover the last minute
        and refresh every 5 seconds, slots appear as they close, about 1.5 seconds after their first shred. Some blocks
        carry no transactions and show 0, a dash means the slot never completed. First tx readable counts from the
        first shred this node received for the block, not from when the leader started, so a node closer to the
        leader sees it sooner. Warning levels are provisional until
        set from a day of real data.
      </p>
      {frozen && (
        <Badge variant="outline" className="fixed bottom-4 left-1/2 -translate-x-1/2 bg-background shadow-sm">
          paused · {waiting} new {unit}{waiting === 1 ? "" : "s"} waiting{held ? " · space to resume" : ""}
        </Badge>
      )}
    </main>
  );
}

/** A copy of the feed taken when the pause starts, null while live. */
function useFrozen(feed: Feed, paused: boolean): Feed | null {
  const [frozen, setFrozen] = useState<Feed | null>(null);
  if (paused && !frozen) setFrozen(feed);
  if (!paused && frozen) setFrozen(null);
  return frozen;
}

function Metric(p: { title: string; value: string; unit: string; note: string; state: State; values: number[] }) {
  const color = p.state === "ok" ? "var(--chart-1)" : states[p.state].color;
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription className="text-[11px] uppercase tracking-wider">{p.title}</CardDescription>
        <CardTitle className="font-mono text-2xl" style={p.state !== "ok" ? { color } : undefined}>
          {p.value}<span className="ml-1 text-sm text-muted-foreground">{p.unit}</span>
        </CardTitle>
        <CardDescription className="text-xs">{p.note}</CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={{ v: { color } }} className="aspect-auto h-11 w-full">
          <AreaChart data={p.values.map((v, i) => ({ i, v }))} margin={{ top: 2, right: 2, bottom: 2, left: 2 }}>
            <YAxis hide domain={["dataMin", "dataMax"]} />
            <Area dataKey="v" type="linear" stroke="var(--color-v)" fill="var(--color-v)" fillOpacity={0.15} isAnimationActive={false} />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}

/** Round axis ticks from 0, in steps of 25, 50 or 100 ms. */
function roundTicks(top: number) {
  const step = top <= 100 ? 25 : top <= 200 ? 50 : 100;
  const last = Math.max(step, Math.ceil(top / step) * step);
  const ticks = [];
  for (let t = 0; t <= last; t += step) ticks.push(t);
  return ticks;
}

/** The bar chart's tooltip line: the real count, even above the chart's cap. */
function missingText(d: { state: State; real: number; total: number | null }) {
  if (d.state === "bad") return "never completed";
  if (!d.total) return `missing ${d.real}`;
  return `missing ${d.real} of ${d.total} (${fmt((d.real / d.total) * 100, 1)}%)`;
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <span className="text-muted-foreground">{k}</span>
      <span className="text-right font-mono">{v}</span>
    </>
  );
}

/** Seconds since the last slot, ticking on its own so the rest of the page does not repaint. */
function Age({ at }: { at: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(t);
  }, []);
  if (!at) return <>-</>;
  const a = (now - at) / 1000;
  return <>{a < 1 ? "just now" : `${fmt(a)} s ago`}</>;
}
