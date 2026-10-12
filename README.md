# shredtap

Watch the shreds that reach your Solana validator and rebuild the blocks from them.

shredtap reads a packet capture of the shreds arriving at a node, puts the FEC sets back together, rebuilds missing pieces with Reed-Solomon and decodes every transaction, with the nanosecond time its shreds arrived. It only reads. It never sends anything and never touches the validator.

![shredtap architecture](docs/architecture.png)

Tested on Solana testnet. Blocks rebuilt from captured shreds match the same blocks fetched with getBlock, transaction for transaction.

Every shred's Merkle proof is checked against its FEC set's root, and every set rebuilt with Reed-Solomon is checked by building its whole Merkle tree again. Given the leader schedule, every set must also carry its slot leader's signature over that root. A changed or forged shred is dropped and counted.

Every transaction also says whether its bytes came over the wire. It is marked rebuilt when one of its data shreds never reached the node by the slot's deadline, so part of it exists only because Reed-Solomon computed it.

> Without a leader schedule, signatures are not checked and the first shred of a set decides its root. Only feed it traffic captured on your own node.

## Build

Needs Rust 1.89 or newer.

```sh
git clone https://github.com/jkrishnad/shred-tap
cd shred-tap
cargo build --release
```

## Usage

Capture shreds on the node with tcpdump, using nanosecond timestamps.

```sh
sudo timeout 60 tcpdump -i <interface> -nn -s 1300 -B 65536 \
  --time-stamp-precision=nano -w shreds.pcap \
  'udp and dst host <node ip> and (udp[4:2] = 1211 or udp[4:2] = 1236)'
```

Save the leader schedule for the epoch of the capture, then decode it.

```sh
solana leader-schedule -ut --epoch <epoch> > leaders.txt
shredtap decode shreds.pcap --out out --leader-schedule leaders.txt
```

Pass `--leader-schedule` again to load more than one epoch.

Use `-` instead of a file to decode a live tcpdump pipe. A capture holds your peers' IP addresses, so keep it private.

## Output

1. `tx.jsonl`, every transaction with its arrival times and whether it was rebuilt
2. `sets.jsonl`, every FEC set, how many data shreds it had when decoded and which never arrived
3. `markers.jsonl`, block header and footer markers
4. `slots.jsonl`, every slot and how it ended
5. `summary.json`, totals for duplicates, late shreds, bad proofs and signatures, lost sets, recovery and rebuilt transactions

A slot's lines are written when it closes, 1.45 s after its first shred with 200 ms slots, so data shreds that arrive late still count as arrived.

## What it showed

From a quiet hour on testnet, with a node in Singapore and 200 ms slots.

1. A FEC set can be rebuilt about 60 ms after its first shred arrives.
2. A whole block takes about 261 ms from its first shred, longer than a slot.
3. 30% of FEC sets never got all 32 data shreds, so Reed-Solomon is used all the time.
