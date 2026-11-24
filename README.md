# GI textile authenticity QR passport

A free, offline tool for a GI-registered weaver cluster: issue a signed provenance passport for each woven piece, print it as a real QR code, and let a buyer holding the cloth check it against the cluster's published key with no network at all.

One binary, the Go standard library only, nothing leaves the machine.

## What it does

A powerloom copy of a Kanchipuram saree, a Pochampally ikat or a Banarasi brocade costs a fraction of the real thing and looks close enough across a shop counter, so the genuine weaver's price collapses towards the copy's. This tool gives a registered cluster something to hand the buyer.

- Records one passport per piece: serial, geographical indication and registration number, the issuer's standing on the GI register and entry number, cluster, weaver and weaver identifier, loom number and loom type, article, warp and weft fibre, zari, length and width off the loom, date off the loom, the certification marks claimed, and how the passport is fastened to the cloth.
- Signs it with the cluster's own Ed25519 key over a canonical, length-prefixed encoding, so no two different passports can share one signature.
- Prints it as a QR code carrying the whole passport and its signature, so checking needs no network and no server.
- Checks a scanned or typed code against a public key the buyer supplies — and refuses to pass without one.
- Gives the buyer a list of things to check against the cloth itself: measure the piece, look along the selvedge, look for the mark's own label, check the tag is stitched in.
- Keeps the cluster's register in one local file, and exports it as a spreadsheet.

## Who it's for

Weaver clusters, co-operative societies and producer companies that are the registered proprietor of a geographical indication or a registered authorised user of one — in India, and in the Philippines since its own GI register opened. Also for the buyer, who needs nothing but the binary and the cluster's published key.

## The named regulation

- **Geographical Indications of Goods (Registration and Protection) Act, 1999** (India) — sections 17 and 21. A registered geographical indication may be used only by its registered proprietor and by registered authorised users, so a passport records which of the two issued it and under which entry.
- **Intellectual Property Code of the Philippines (Republic Act No. 8293)**, with the Intellectual Property Office of the Philippines' **Rules and Regulations on Geographical Indications, 2022**, under which the Philippine GI register was opened.
- **Handloom Mark** (Ministry of Textiles, through the Textiles Committee) certifies handwoven cloth. A passport claiming it on a powerloom or mill-made piece is refused.
- **Silk Mark** (Silk Mark Organisation of India, Central Silk Board) certifies natural silk. A passport claiming it with no silk in either warp or weft is refused; a silk-and-cotton blend draws a warning.

Neither mark is granted or checked by this tool: each is a separately issued label with its own number. The **GI registration number is yours to supply** — this tool ships no list of registrations, because it could not keep one current or verify one.

## Install and run

```sh
git clone https://github.com/sreenivas-sadhu-prabhakara/gi-textile-authenticity-qr-passport.git
cd gi-textile-authenticity-qr-passport
go build -o gi-textile-passport .
./gi-textile-passport

# or without building first
go run .

# prove the QR generator works on this machine before printing 500 tags
./gi-textile-passport -qr-selftest

# your own register, and the cluster's key read from a file you control
./gi-textile-passport -data ~/society/passports-2026.json -key ~/society/cluster.key
```

Then open <http://127.0.0.1:8080>.

Flags: `-addr` (default `127.0.0.1:8080`), `-data` (default `./gi-textile-passport-data.json`), `-key` (optional path to the cluster's private signing key), `-qr-selftest`.

## Where data is stored

One JSON file, where you point `-data` and nowhere else. Each save replaces it atomically through a temporary file and a rename, so an interrupted write leaves the previous register intact, and the file is written readable by its owner only.

**The signing key is never written to that file.** The tool reads it from the file `-key` points at, or from whoever is issuing, and holds it in memory only while it signs. A key generated in the interface is shown once and saved nowhere.

Nothing leaves the machine: no telemetry, no update check, no connection to any registry or authority. The tool listens on 127.0.0.1 unless you tell it otherwise.

## The QR code

The symbol is generated here, in Go, from the specification — Reed-Solomon over GF(256), all forty versions at all four error-correction levels, byte and alphanumeric modes, module placement, the eight masks and their scoring, and the BCH-protected format and version information — and rendered to PNG with the standard library.

It was checked module for module against an independent QR Code implementation across 1,280 symbols (every version, every level, both modes, payloads filled to capacity, forced masks and automatic mask selection), and the rendered images were decoded by an ordinary off-the-shelf barcode scanner. `-qr-selftest` runs the whole loop on your machine: encode, render, read the image back to modules, decode, recovering the level and mask from the symbol itself.

Not implemented, plainly: numeric mode (digits encode in alphanumeric mode — correct, slightly larger), kanji mode, Micro QR, structured append, and error *correction* when reading. A damaged block is reported as damaged, never repaired, because a half-recovered signed passport must not be presented as genuine.

The QR carries the passport itself, not a web address: a link would need a server kept running and a buyer with a connection. A typical passport comes to a 637-character code in a version 16 symbol, 81 modules across — about 0.45 mm a module printed 40 mm square, which wants 300 dpi or better.

## Scope and accuracy

A valid signature means two things and no more: the holder of that private key issued this passport, and not one character of it has changed since.

**It does not prove the cloth in the buyer's hands is the piece described.** A passport is data; it can be photographed, copied and sewn onto a counterfeit piece, and every copy verifies perfectly because every copy is the same bytes. The only thing that ties a passport to a particular piece is a **physical binding** — a tag stitched into that piece, or a mark woven into its selvedge. That is the cluster's work and the buyer's inspection, not something software can do. The tool records which binding was used and says so when the answer is none.

It does not prove the facts are true: the cluster typed them in. It does not check the GI register, the authorised-user entry or either certification mark — those live with their authorities. It cannot tell you whether a passport has been printed once or a thousand times; only the cluster's register can, by looking the serial up.

The measurement ranges it judges against are craft norms, not law, and they only ever produce a warning. Confirm the position on the Act, the registration and the marks with the authorities named above before relying on anything here.

MIT licensed.
