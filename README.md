# shredtap

Watch the shreds that reach your Solana validator and rebuild the blocks from them.

shredtap reads a packet capture of the shreds arriving at a node, puts the FEC sets back together, rebuilds missing pieces with Reed-Solomon and decodes every transaction, with the nanosecond time its shreds arrived. It only reads. It never sends anything and never touches the validator.

![shredtap architecture](docs/architecture.png)

Tested on Solana testnet. Blocks rebuilt from captured shreds match the same blocks fetched with getBlock, transaction for transaction.

> shredtap does not verify Merkle proofs or leader signatures. Only feed it traffic captured on your own node.

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

Then decode it.

```sh
shredtap decode shreds.pcap --out out
```

Use `-` instead of a file to decode a live tcpdump pipe. A capture holds your peers' IP addresses, so keep it private.

## Output

1. `tx.jsonl`, every transaction with its arrival times
2. `sets.jsonl`, every FEC set and how many data shreds it had when decoded
3. `markers.jsonl`, block header and footer markers
4. `slots.jsonl`, every slot and how it ended
5. `summary.json`, totals for duplicates, late shreds, lost sets and recovery

## What it showed

From a quiet hour on testnet, with a node in Singapore and 200 ms slots.

1. A FEC set can be rebuilt about 60 ms after its first shred arrives.
2. A whole block takes about 261 ms from its first shred, longer than a slot.
3. 30% of FEC sets never got all 32 data shreds, so Reed-Solomon is used all the time.
