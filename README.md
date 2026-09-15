# PythonLoRaMoDem

A complete **LoRa / Meshtastic modem in pure Python** that drives a **HackRF** directly through libhackrf.
No GNU Radio, no SDRangel: type a message, it goes on air as a real Meshtastic packet, and the same radio
flips to receive and decodes what comes back.

```
> hello mesh
23:31:45 TX id 532bab7c -> broadcast (39 B, 0.56s on air) want_ack
23:31:47 RX cfo=+135Hz [Bob (!a2b4c6d8) -> !a1b2c3d4, id 1f2e3d4c, 0 hops] ROUTING/ACK for 532bab7c: NONE (ACK for YOUR message!)
```

## What it does

* **LoRa PHY, transmit and receive** — chirp spread spectrum modulation/demodulation, preamble detection,
  fractional CFO/STO estimation, sampling-frequency-offset tracking, explicit header with checksum,
  Hamming FEC, diagonal interleaver, Gray mapping, whitening and CRC16. Bit-exact port of
  [gr-lora_sdr](https://github.com/tapparelj/gr-lora_sdr) (Tapparel et al., EPFL).
* **Meshtastic layer** — 16-byte on-air header, AES-128/256-CTR channel encryption (default `LongFast`
  PSK, `simpleN`, hex or base64 keys), channel hash, and the official protobufs for text, node info,
  position, telemetry and routing/ACK. Uses the `meshtastic` Python package for the protobuf definitions.
* **HackRF control** via libhackrf (ctypes): open once, `start_rx` / `start_tx` on the same handle, ~0.6 s
  turnaround, so ACKs to your own messages are caught. Tunes 200 kHz off-channel and shifts digitally to keep
  the HackRF's DC spike out of the LoRa channel.
* **Console chat** with `/ack`, `/to !nodeid`, `/nodeinfo` (announce your name), `/hex`, `/quit`.
* **Offline test modes** so you can validate without a second radio: encode→decode loopback with realistic
  crystal offsets, decode of recorded `.sdriq` IQ files, and export of your own bursts to `.sdriq`.

Default radio profile: **Meshtastic LONG_FAST on EU_868** — SF11, 250 kHz, CR 4/5, sync word 0x2B,
16-symbol preamble, 869.525 MHz. Change the constants at the top of `meshchat.py` for other presets/regions.

## Requirements

* Python 3.11+ with `numpy`, `pycryptodome`, `meshtastic` (`pip install -r requirements.txt`)
* A HackRF (One or Pro) with libhackrf available: on Windows `hackrf.dll` from the
  [hackrf-tools release](https://github.com/greatscottgadgets/hackrf/releases), PothosSDR, or SDRangel's
  bundled copy; on Linux `libhackrf.so` from your distro. Point to it with `--dll-dir` or `HACKRF_DLL_DIR`
  if it is not found automatically.
* If your HackRF runs PortaPack/Mayhem firmware, switch it to **HackRF mode** first (menu *HackRF*).
* Nothing else may hold the HackRF open (close SDRangel, GQRX, etc.).

Developed and tested on Windows 11 with a HackRF Pro (Mayhem "HackRF mode"), Python 3.14, numpy 2.5.

## Usage

```bash
py meshchat.py                          # interactive chat
py meshchat.py --ack                    # request ACKs for your texts
py meshchat.py --from 0xDEADBEEF --name "My Node" --short MYND
py meshchat.py --send "hello" --listen 30   # non-interactive: send once, listen 30 s, exit

py meshchat.py --selftest               # loopback at 0/+4/-6/+10 ppm crystal offset (no radio needed)
py meshchat.py --decode-file rx.sdriq   # decode a 2 MS/s .sdriq recording (e.g. from SDRangel)
py meshchat.py --encode-file tx.sdriq "text"   # write your burst as .sdriq
```

Options: `--gain` (TX VGA 0..47, default 30), `--lna` / `--vga` (RX gains, 32 / 20), `--key default|simpleN|hex:..|base64:..`,
`--dll-dir`, `--verbose` (prints sync diagnostics: preamble bins, CFO/STO, sync words, header).

## How it was validated

* **Interoperability, RX:** decodes a Meshtastic burst encoded by an independent implementation (SDRangel's
  Meshtastic modulator) with a valid CRC and the expected text and packet id.
* **Interoperability, TX:** rebuilding that packet with this code (same id/sender/flags) produces
  **byte-identical** output, including the AES-CTR ciphertext and channel hash.
* **Loopback under realistic impairments:** frequency offset *and* the matching sample-clock drift of a
  ±10 ppm crystal, plus noise: all frames decode, CFO estimated exactly.
* **Live:** transmit + receive on a HackRF runs in real time (≈15 ms of processing per 65 ms of samples).

## How it works (one paragraph)

TX: text → `Data` protobuf → AES-CTR with nonce = (packet id, sender) → 16-byte header + ciphertext →
LoRa nibbles (header, whitened payload, CRC) → Hamming (4/8 for the header block, 4/CR after) →
diagonal interleaver → inverse Gray (+1) → chirps at 8 samples/chip → shifted −200 kHz → int8 → libhackrf.
RX: libhackrf int8 → +200 kHz shift → FIR decimate to 2 samples/chip → sliding dechirp/FFT looks for
≥8 consistent preamble peaks → Bernier fractional CFO, Cui-Yang fractional STO → sync words (16, 88) →
2.25 downchirps give integer CFO → payload demod with SFO tracking → Gray → deinterleave → Hamming →
header check → dewhiten → CRC → Meshtastic decrypt → protobuf → print.

## Limitations / notes

* Half duplex: one HackRF, so nothing is received while transmitting.
* Only one channel/preset is compiled in at a time (constants at the top of the file).
* No store-and-forward, no rebroadcast; this is an end node, not a router.
* Transmitting is regulated. 869.4–869.65 MHz is a licence-free SRD band in Europe with power and duty-cycle
  limits; know your local rules, use an antenna, keep tests short, and use `want_ack` sparingly on the
  public LongFast channel.

## Credits and license

The LoRa physical layer is a port of **gr-lora_sdr** by Joachim Tapparel and the EPFL Telecommunication
Circuits Laboratory (GPL-3.0). Meshtastic protobufs from the **meshtastic** Python package. Written with
the help of Claude (Anthropic).

Licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).
