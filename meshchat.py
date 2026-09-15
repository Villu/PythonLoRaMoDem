#!/usr/bin/env python
# SPDX-License-Identifier: GPL-3.0-or-later
# PythonLoRaMoDem - LoRa / Meshtastic modem for HackRF in pure Python.
# Copyright (C) 2026 Villu Sepman
#
# The LoRa physical layer in this file is a port of gr-lora_sdr,
# Copyright (C) Joachim Tapparel, EPFL Telecommunication Circuits Laboratory,
# licensed under the GNU General Public License v3.0 (https://github.com/tapparelj/gr-lora_sdr).
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version. It is distributed WITHOUT ANY WARRANTY; see the
# GNU General Public License for details: https://www.gnu.org/licenses/gpl-3.0.html
"""
meshchat.py - standalone Meshtastic LoRa chat over a HackRF, no SDRangel.

  Type a line -> it is built into a Meshtastic packet (default LongFast key), LoRa-modulated (SF11/250 kHz/CR 4/5,
  sync 0x2B, EU_868 869.525 MHz), transmitted through libhackrf, then the same HackRF handle flips back to receive
  and decodes every LoRa frame it hears: text, node info, positions, telemetry, and ACKs to your own messages.

LoRa PHY is a faithful port of gr-lora_sdr (Tapparel et al., EPFL) - header/CRC/whitening/Hamming/interleaver/gray
conventions, chirp construction, preamble detection, CFO/STO estimation and SFO compensation.

Usage:
  py meshchat.py                      live chat (HackRF must be in HackRF mode and free)
  py meshchat.py --selftest           encode -> decode loopback with injected offsets (no hardware)
  py meshchat.py --decode-file F      decode a 2 MS/s .sdriq (e.g. SDRangel's mesh_tx.sdriq) - validates RX
  py meshchat.py --encode-file F "t"  write my TX burst as .sdriq (feed to SDRangel FileInput to validate TX)
Options: --from 0xA1B2C3D4 --name "HackRF Pro" --short HKRF --gain 30 --lna 32 --vga 20 --key default --ack
In chat: /ack on|off, /to !nodeid|all, /nodeinfo, /hex, /quit
"""
import sys, os, time, struct, threading, queue, argparse, base64, random, ctypes
import numpy as np
from Crypto.Cipher import AES

# ============================================================ LoRa parameters (Meshtastic LONG_FAST)
SF = 11
BW = 250_000
CR = 1                     # 4/5
PREAMBLE_LEN = 16          # Meshtastic
SYNC_WORD = 0x2B           # Meshtastic private sync word
HAS_CRC = True
LDRO = False               # LongFast: symbol 8.19 ms < 16 ms
N = 1 << SF
SYNC = [((SYNC_WORD & 0xF0) >> 4) << 3, (SYNC_WORD & 0x0F) << 3]   # [16, 88]
FREQ_HZ = 869_525_000
HACKRF_RATE = 2_000_000
TX_OS = HACKRF_RATE // BW              # 8 samples per chip on TX
RX_OS = 2                               # 2 samples per chip in the receiver (for half-sample timing)
RX_RATE = BW * RX_OS                    # 500 kS/s
DECIM = HACKRF_RATE // RX_RATE          # 4
SPS = N * RX_OS                         # samples per symbol at RX rate
LO_OFFSET_HZ = 200_000                  # tune the HackRF LO 200 kHz high; shift digitally so the DC spike stays out of the channel
N_UP_REQ = 8                            # consecutive preamble upchirps required for detection

WHITENING = bytes([
    0xFF,0xFE,0xFC,0xF8,0xF0,0xE1,0xC2,0x85,0x0B,0x17,0x2F,0x5E,0xBC,0x78,0xF1,0xE3,0xC6,0x8D,0x1A,0x34,0x68,0xD0,0xA0,0x40,0x80,0x01,0x02,0x04,0x08,0x11,0x23,0x47,
    0x8E,0x1C,0x38,0x71,0xE2,0xC4,0x89,0x12,0x25,0x4B,0x97,0x2E,0x5C,0xB8,0x70,0xE0,0xC0,0x81,0x03,0x06,0x0C,0x19,0x32,0x64,0xC9,0x92,0x24,0x49,0x93,0x26,0x4D,0x9B,
    0x37,0x6E,0xDC,0xB9,0x72,0xE4,0xC8,0x90,0x20,0x41,0x82,0x05,0x0A,0x15,0x2B,0x56,0xAD,0x5B,0xB6,0x6D,0xDA,0xB5,0x6B,0xD6,0xAC,0x59,0xB2,0x65,0xCB,0x96,0x2C,0x58,
    0xB0,0x61,0xC3,0x87,0x0F,0x1F,0x3E,0x7D,0xFB,0xF6,0xED,0xDB,0xB7,0x6F,0xDE,0xBD,0x7A,0xF5,0xEB,0xD7,0xAE,0x5D,0xBA,0x74,0xE8,0xD1,0xA2,0x44,0x88,0x10,0x21,0x43,
    0x86,0x0D,0x1B,0x36,0x6C,0xD8,0xB1,0x63,0xC7,0x8F,0x1E,0x3C,0x79,0xF3,0xE7,0xCE,0x9C,0x39,0x73,0xE6,0xCC,0x98,0x31,0x62,0xC5,0x8B,0x16,0x2D,0x5A,0xB4,0x69,0xD2,
    0xA4,0x48,0x91,0x22,0x45,0x8A,0x14,0x29,0x52,0xA5,0x4A,0x95,0x2A,0x54,0xA9,0x53,0xA7,0x4E,0x9D,0x3B,0x77,0xEE,0xDD,0xBB,0x76,0xEC,0xD9,0xB3,0x67,0xCF,0x9E,0x3D,
    0x7B,0xF7,0xEF,0xDF,0xBF,0x7E,0xFD,0xFA,0xF4,0xE9,0xD3,0xA6,0x4C,0x99,0x33,0x66,0xCD,0x9A,0x35,0x6A,0xD4,0xA8,0x51,0xA3,0x46,0x8C,0x18,0x30,0x60,0xC1,0x83,0x07,
    0x0E,0x1D,0x3A,0x75,0xEA,0xD5,0xAA,0x55,0xAB,0x57,0xAF,0x5F,0xBE,0x7C,0xF9,0xF2,0xE5,0xCA,0x94,0x28,0x50,0xA1,0x42,0x84,0x09,0x13,0x27,0x4F,0x9F,0x3F,0x7F])

# ============================================================ small helpers
def int2bool(v, n):            # MSB first
    return [(v >> (n - 1 - i)) & 1 for i in range(n)]

def bool2int(bits):
    v = 0
    for b in bits:
        v = (v << 1) | int(b)
    return v

def crc16_byte(crc, b):
    for _ in range(8):
        if ((crc & 0x8000) >> 8) ^ (b & 0x80):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF
        else:
            crc = (crc << 1) & 0xFFFF
        b = (b << 1) & 0xFF
    return crc

def lora_crc(payload):
    crc = 0
    for i in range(len(payload) - 2):
        crc = crc16_byte(crc, payload[i])
    crc ^= payload[-1] ^ (payload[-2] << 8)
    return crc & 0xFFFF

def header_checksum(h0, h1, h2):
    b = lambda x, k: (x >> k) & 1
    c4 = b(h0,3) ^ b(h0,2) ^ b(h0,1) ^ b(h0,0)
    c3 = b(h0,3) ^ b(h1,3) ^ b(h1,2) ^ b(h1,1) ^ b(h2,0)
    c2 = b(h0,2) ^ b(h1,3) ^ b(h1,0) ^ b(h2,3) ^ b(h2,1)
    c1 = b(h0,1) ^ b(h1,2) ^ b(h1,0) ^ b(h2,2) ^ b(h2,1) ^ b(h2,0)
    c0 = b(h0,0) ^ b(h1,1) ^ b(h2,3) ^ b(h2,2) ^ b(h2,1) ^ b(h2,0)
    return c4, (c3 << 3) | (c2 << 2) | (c1 << 1) | c0

def build_upchirp(id_, sf=SF, os_=1):
    Nn = 1 << sf
    n = np.arange(Nn * os_, dtype=np.float64)
    n_fold = Nn * os_ - id_ * os_
    slope = np.where(n < n_fold, id_ / Nn - 0.5, id_ / Nn - 1.5)
    return np.exp(2j * np.pi * (n * n / (2 * Nn) / (os_ ** 2) + slope * n / os_)).astype(np.complex64)

UP1 = build_upchirp(0, SF, 1)
DOWN1 = np.conj(UP1)

# ============================================================ LoRa encoder (TX)
def lora_encode(payload: bytes):
    """bytes -> list of LoRa symbols (0..N-1), explicit header, CRC, LongFast params."""
    n = len(payload)
    assert 1 <= n <= 255
    h0, h1, h2 = n >> 4, n & 0xF, (CR << 1) | int(HAS_CRC)
    c4, c30 = header_checksum(h0, h1, h2)
    nibbles = [h0, h1, h2, c4, c30]
    for i, byte in enumerate(payload):
        w = byte ^ WHITENING[i]
        nibbles += [w & 0xF, w >> 4]
    if HAS_CRC:
        crc = lora_crc(payload)
        nibbles += [crc & 0xF, (crc >> 4) & 0xF, (crc >> 8) & 0xF, (crc >> 12) & 0xF]
    # Hamming
    cws = []
    for cnt, nib in enumerate(nibbles):
        cr_app = 4 if cnt < SF - 2 else CR
        d = int2bool(nib, 4)
        if cr_app != 1:
            p0 = d[3] ^ d[2] ^ d[1]; p1 = d[2] ^ d[1] ^ d[0]; p2 = d[3] ^ d[2] ^ d[0]; p3 = d[3] ^ d[1] ^ d[0]
            cw = (d[3] << 7 | d[2] << 6 | d[1] << 5 | d[0] << 4 | p0 << 3 | p1 << 2 | p2 << 1 | p3) >> (4 - cr_app)
        else:
            p4 = d[0] ^ d[1] ^ d[2] ^ d[3]
            cw = d[3] << 4 | d[2] << 3 | d[1] << 2 | d[0] << 1 | p4
        cws.append(cw)
    # interleave + gray demap
    syms = []
    i = 0
    first = True
    while i < len(cws):
        cw_len = 4 + (4 if first else CR)
        sf_app = (SF - 2) if (first or LDRO) else SF
        block = cws[i:i + sf_app]
        block += [0] * (sf_app - len(block))
        cw_bin = [int2bool(c, cw_len) for c in block]
        for ii in range(cw_len):
            inter = [0] * SF
            for j in range(sf_app):
                inter[j] = cw_bin[(ii - j - 1) % sf_app][ii]
            if first or LDRO:
                inter[sf_app] = sum(inter) % 2
            v = bool2int(inter)
            g = v
            for j in range(1, SF):
                g ^= v >> j
            syms.append((g + 1) % N)
        i += sf_app
        first = False
    return syms

def lora_modulate(symbols, os_=TX_OS):
    """symbols -> complex64 baseband at BW*os_ (preamble, sync, 2.25 downchirps, payload)."""
    up = build_upchirp(0, SF, os_)
    down = np.conj(up)
    parts = [up] * PREAMBLE_LEN
    parts += [build_upchirp(SYNC[0], SF, os_), build_upchirp(SYNC[1], SF, os_)]
    parts += [down, down, down[: len(down) // 4]]
    parts += [build_upchirp(s, SF, os_) for s in symbols]
    return np.concatenate(parts)

# ============================================================ LoRa decoder (RX)
class LoRaRx:
    """Stream decoder at RX_RATE (RX_OS samples/chip). feed(x) -> list of (payload_bytes, info)."""
    def __init__(self, verbose=False):
        self.buf = np.zeros(0, np.complex64)
        self.base = 0            # absolute index of buf[0]
        self.p = 0               # absolute index of next DETECT window
        self.verbose = verbose
        self.prev_bin = -1
        self.cnt = 0
        self.bins = []
        self.pending = None
        self.n = np.arange(N)

    # --- helpers
    def _win(self, start, os_off=0):
        """os=1 view of one symbol starting at absolute os-domain index `start` (+ os//2 + os_off)."""
        s = start - self.base + RX_OS // 2 + os_off
        return self.buf[s: s + SPS: RX_OS]

    @staticmethod
    def _sym_val(w, ref):
        f = np.fft.fft(w * ref)
        mag = np.abs(f) ** 2
        return int(np.argmax(mag)), f, mag

    def _avail(self, start, nsym):
        return (start - self.base) + nsym * SPS + RX_OS < len(self.buf)

    def feed(self, x):
        self.buf = np.concatenate([self.buf, x.astype(np.complex64)])
        out = []
        # a detection that was waiting for more samples: retry it first
        if getattr(self, "pending", None) is not None:
            p_first, k_hat = self.pending
            res = self._sync_and_decode(p_first, k_hat, out)
            if res == 'more':
                self._trim(p_first)
                return out
            self.pending = None
            self.p = res if isinstance(res, int) else self.p + SPS
            self.prev_bin = -1; self.cnt = 0; self.bins = []
        while True:
            if not self._avail(self.p, 2):
                break
            w = self._win(self.p)
            if len(w) < N:
                break
            b, _, mag = self._sym_val(w, DOWN1)
            pk = float(mag[b]); mean = float(mag.mean()) if mag.size else 0.0
            if pk <= 0 or mean <= 0 or pk < 10.0 * mean:
                b = -1                                  # no usable peak (silence / noise)
            if b >= 0 and self.prev_bin >= 0 and abs(((b - self.prev_bin + 1) % N) - 1) <= 1:
                self.cnt += 1
                self.bins.append(b)
            else:
                self.cnt = 1 if b >= 0 else 0
                self.bins = [b] if b >= 0 else []
            self.prev_bin = b
            if self.cnt >= N_UP_REQ:
                k_hat = max(set(self.bins), key=self.bins.count)
                p_first = self.p - (self.cnt - 1) * SPS
                if self.verbose:
                    print(f"  [detect] preamble run at p={p_first} bins={self.bins} k_hat={k_hat}")
                res = self._sync_and_decode(p_first, k_hat, out)
                self.prev_bin = -1; self.cnt = 0; self.bins = []
                if res == 'more':
                    self.pending = (p_first, k_hat)
                    break
                self.p = res if isinstance(res, int) else self.p + SPS
                continue
            self.p += SPS
        self._trim(self.pending[0] if getattr(self, "pending", None) is not None else self.p)
        return out

    def _trim(self, anchor):
        keep_from = anchor - (N_UP_REQ + 3) * SPS - 4 * RX_OS
        if keep_from > self.base:
            cut = keep_from - self.base
            self.buf = self.buf[cut:]
            self.base += cut

    def _sync_and_decode(self, p_first, k_hat, out):
        up_use = N_UP_REQ - 1
        # aligned preamble windows (equivalent to preamble_raw[N-k_hat + i*N])
        al0 = p_first + SPS - k_hat * RX_OS
        # need: preamble windows + 2 sync + 2.25 down + 8 header symbols at least
        if not self._avail(al0, up_use + PREAMBLE_LEN + 4 + 10):
            return 'more'
        # --- CFO frac (Bernier)
        k0 = []; k0mag = []; fftv = []
        for i in range(up_use):
            w = self._win(al0 + i * SPS)
            bi, f, mag = self._sym_val(w, DOWN1)
            k0.append(bi); k0mag.append(mag[bi]); fftv.append(f)
        idx_max = k0[int(np.argmax(k0mag))]
        four = 0j
        for i in range(up_use - 1):
            four += fftv[i][idx_max] * np.conj(fftv[i + 1][idx_max])
        cfo_frac = -np.angle(four) / (2 * np.pi)
        cfo_corr = np.exp(-2j * np.pi * cfo_frac / N * self.n).astype(np.complex64)
        # --- STO frac (Cui Yang), on CFO-frac corrected preamble
        acc = np.zeros(2 * N)
        for i in range(up_use):
            w = self._win(al0 + i * SPS) * cfo_corr
            d = w * DOWN1
            f = np.fft.fft(d, 2 * N)
            acc += np.abs(f) ** 2
        kk = int(np.argmax(acc))
        Ym1, Y0, Y1 = acc[(kk - 1) % (2 * N)], acc[kk], acc[(kk + 1) % (2 * N)]
        u = 64 * N / 406.5506497; v = u * 2.4674
        wa = (Y1 - Ym1) / (u * (Y1 + Ym1) + v * Y0)
        ka = wa * N / np.pi
        k_res = ((kk + ka) / 2) % 1.0
        sto_frac = k_res - (1 if k_res > 0.5 else 0)
        if not np.isfinite(sto_frac):
            return p_first + SPS
        os_off = -int(round(sto_frac * RX_OS))
        if self.verbose:
            print(f"  [sync] cfo_frac={cfo_frac:+.3f} bins  sto_frac={sto_frac:+.3f}  k0s={k0}")
        # --- walk: additional upchirps, NET_ID1, NET_ID2, DOWN1, DOWN2, QUARTER
        p_cur = al0 + up_use * SPS
        additional = 0
        netid1 = netid2 = None
        state = 'NET1'
        down_val = None
        while True:
            if not self._avail(p_cur, 2):
                return 'more'
            w = self._win(p_cur, os_off) * cfo_corr
            if state == 'NET1':
                b, _, _ = self._sym_val(w, DOWN1)
                if b in (0, 1, N - 1):
                    additional += 1
                    if additional > PREAMBLE_LEN:
                        return p_cur              # not a frame
                else:
                    netid1 = b; state = 'NET2'
            elif state == 'NET2':
                netid2, _, _ = self._sym_val(w, DOWN1); state = 'D1'
            elif state == 'D1':
                state = 'D2'
            elif state == 'D2':
                down_val, _, _ = self._sym_val(w, UP1); state = 'Q'
            elif state == 'Q':
                break
            p_cur += SPS
        # p_cur now = start of the quarter downchirp window
        cfo_int = int(np.floor(down_val / 2)) if down_val < N // 2 else int(np.floor((down_val - N) / 2))
        if self.verbose:
            print(f"  [sync] additional_up={additional} netid1={netid1} netid2={netid2} down_val={down_val} -> cfo_int={cfo_int}")
        # refined sto (after CFO int correction of preamble) - gr does this; small gain, keep simple: reuse sto_frac
        sfo_hat = (cfo_int + cfo_frac) * BW / FREQ_HZ
        sto_frac_t = sto_frac + sfo_hat * PREAMBLE_LEN
        if abs(sto_frac_t) > 0.5:
            sto_frac_t += -1 if sto_frac_t > 0 else 1
        # verify sync words with full correction
        ref_down = (np.conj(build_upchirp(cfo_int % N, SF, 1)) * cfo_corr).astype(np.complex64)
        start_off = RX_OS // 2 - int(round(sto_frac_t * RX_OS)) + RX_OS * (N // 4 + cfo_int)
        # net id windows re-cut with cfo_int timing shift (start_off minus the quarter symbol)
        def cut(abs_start):
            s = abs_start - self.base + RX_OS // 2 - int(round(sto_frac_t * RX_OS)) + RX_OS * cfo_int
            return self.buf[s: s + SPS: RX_OS]
        w1 = cut(p_cur - 4 * SPS); w2 = cut(p_cur - 3 * SPS)
        if len(w1) < N or len(w2) < N:
            return 'more'
        nid1, _, _ = self._sym_val(w1, ref_down)
        nid2, _, _ = self._sym_val(w2, ref_down)
        if self.verbose:
            print(f"  [sync] corrected netids: {nid1},{nid2} (want {SYNC}) sfo_hat={sfo_hat:+.5f}")
        one_off = 0
        if abs(nid1 - SYNC[0]) > 2:
            if abs(nid1 - SYNC[1]) <= 2:
                # netid1 window actually holds sync word 2 -> we are one symbol late
                net_id_off = nid1 - SYNC[1]; one_off = 1
            else:
                if self.verbose:
                    print(f"  [sync] reject: netid1={nid1} netid2={nid2} (want {SYNC})")
                return p_cur
        else:
            net_id_off = nid1 - SYNC[0]
            if (nid2 - net_id_off) % N != SYNC[1]:
                if self.verbose:
                    print(f"  [sync] reject: netid1={nid1} netid2={nid2} (want {SYNC})")
                return p_cur
        # payload start (os-domain absolute index of the first os=1 sample)
        sto_frac_t += sfo_hat * 4.25
        pay0 = p_cur + (RX_OS // 2 - int(round(sto_frac_t * RX_OS)) + RX_OS * (N // 4 + cfo_int)) - RX_OS * net_id_off
        if one_off:
            pay0 -= SPS
        sfo_cum = ((sto_frac_t * RX_OS) - round(sto_frac_t * RX_OS)) / RX_OS
        # --- demodulate symbols with SFO tracking
        def demod(nsym, start_idx, sfo_cum):
            syms = []
            s = start_idx
            for k in range(nsym):
                if s - self.base + SPS > len(self.buf):
                    return None, s, sfo_cum
                w = self.buf[s - self.base: s - self.base + SPS: RX_OS]
                if len(w) < N:
                    return None, s, sfo_cum
                b, _, _ = self._sym_val(w, ref_down)
                syms.append((b - 1) % N)
                s += SPS
                if abs(sfo_cum) > 1.0 / 2 / RX_OS:
                    sgn = 1 if sfo_cum > 0 else -1
                    s -= sgn
                    sfo_cum -= sgn * 1.0 / RX_OS
                sfo_cum += sfo_hat
            return syms, s, sfo_cum
        hdr_syms, s_after, sfo_cum = demod(8, pay0, sfo_cum)
        if hdr_syms is None:
            return 'more'
        hdr = self._decode_block([v // 4 for v in hdr_syms], header=True)
        h = hdr[:5]
        if self.verbose:
            print(f"  [hdr] symbols={hdr_syms} nibbles={hdr}")
        pay_len = (h[0] << 4) + h[1]
        has_crc = h[2] & 1
        cr = h[2] >> 1
        chk = ((h[3] & 1) << 4) + h[4]
        c4, c30 = header_checksum(h[0], h[1], h[2])
        if chk != ((c4 << 4) | c30) or pay_len == 0 or cr < 1 or cr > 4:
            if self.verbose:
                print(f"  [hdr] invalid (len={pay_len} cr={cr} crc={has_crc} chk={chk} vs {(c4<<4)|c30})")
            return p_cur
        nib_total = 2 * pay_len + (4 if has_crc else 0) + 5
        n_blocks = int(np.ceil(max(nib_total - SF + 2, 0) / (SF - 2 * int(LDRO))))
        n_pay_syms = n_blocks * (cr + 4)
        if not self._avail(s_after, n_pay_syms + 1):
            return 'more'
        pay_syms, s_end, _ = demod(n_pay_syms, s_after, sfo_cum)
        if pay_syms is None:
            return 'more'
        nibbles = hdr[5:]
        for bi in range(n_blocks):
            blk = pay_syms[bi * (cr + 4):(bi + 1) * (cr + 4)]
            nibbles += self._decode_block(blk, header=False, cr=cr)
        # dewhiten
        data = bytearray()
        for i in range(pay_len):
            lo = nibbles[2 * i] ^ (WHITENING[i] & 0x0F)
            hi = nibbles[2 * i + 1] ^ (WHITENING[i] >> 4)
            data.append((hi << 4) | lo)
        crc_ok = None
        if has_crc and pay_len >= 2:
            j = 2 * pay_len
            rx_crc = (nibbles[j + 1] << 4 | nibbles[j]) | ((nibbles[j + 3] << 4 | nibbles[j + 2]) << 8)
            crc_ok = (lora_crc(bytes(data)) == rx_crc)
        info = dict(cfo_bins=cfo_int + cfo_frac, cfo_hz=(cfo_int + cfo_frac) * BW / N, sto=k_hat - cfo_int + sto_frac,
                    cr=cr, crc_ok=crc_ok, netid=(nid1, nid2), len=pay_len)
        out.append((bytes(data), info))
        return s_end + SPS   # resume detection after the frame

    def _decode_block(self, syms, header, cr=CR):
        """gray mapping + deinterleave + hamming -> list of nibbles for one block."""
        sf_app = (SF - 2) if (header or LDRO) else SF
        cw_len = 8 if header else cr + 4
        cr_app = 4 if header else cr
        gs = [s ^ (s >> 1) for s in syms]
        inter = [int2bool(g, sf_app) for g in gs]
        deinter = [[0] * cw_len for _ in range(sf_app)]
        for i in range(cw_len):
            for j in range(sf_app):
                deinter[(i - j - 1) % sf_app][i] = inter[i][j]
        nibbles = []
        for k in range(sf_app):
            cw = deinter[k]
            d = [cw[3], cw[2], cw[1], cw[0]]
            if cr_app >= 3:
                if cr_app == 4 and sum(cw) % 2 == 0:
                    pass  # even number of errors: don't correct
                else:
                    s0 = cw[0] ^ cw[1] ^ cw[2] ^ cw[4]
                    s1 = cw[1] ^ cw[2] ^ cw[3] ^ cw[5]
                    s2 = cw[0] ^ cw[1] ^ cw[3] ^ cw[6]
                    syn = s0 + (s1 << 1) + (s2 << 2)
                    if syn == 5: d[3] ^= 1
                    elif syn == 7: d[2] ^= 1
                    elif syn == 3: d[1] ^= 1
                    elif syn == 6: d[0] ^= 1
            nibbles.append(bool2int(d))
        return nibbles

# ============================================================ Meshtastic layer
from meshtastic.protobuf import mesh_pb2, portnums_pb2, telemetry_pb2

DEFAULT_PSK = base64.b64decode("1PG7OiApB1nwvP+rz05pAQ==")

def resolve_key(spec):
    if spec in ("default", "AQ==", "1"):
        return DEFAULT_PSK
    if spec.startswith("simple"):
        k = bytearray(DEFAULT_PSK); k[-1] = (k[-1] + int(spec[6:]) - 1) & 0xFF; return bytes(k)
    if spec.startswith("hex:"):
        return bytes.fromhex(spec[4:])
    if spec.startswith("base64:"):
        return base64.b64decode(spec[7:])
    if spec == "none":
        return b""
    return base64.b64decode(spec)

def xor_hash(b):
    h = 0
    for x in b: h ^= x
    return h

def channel_hash(name, key):
    return xor_hash(name.encode()) ^ xor_hash(key)

def mesh_crypt(key, pkt_id, from_id, data):
    if not key:
        return data
    nonce = struct.pack('<IIII', pkt_id & 0xFFFFFFFF, 0, from_id & 0xFFFFFFFF, 0)
    c = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(nonce, 'big'))
    return c.encrypt(data)

def build_packet(from_id, to_id, portnum, payload, key, channel="LongFast", hop_limit=3, want_ack=False,
                 request_id=0, pkt_id=None):
    if pkt_id is None:
        pkt_id = random.getrandbits(32) | 0x80000000 if False else random.randint(0x10000, 0x7FFFFFFF)
    d = mesh_pb2.Data(portnum=portnum, payload=payload)
    if request_id:
        d.request_id = request_id
    enc = mesh_crypt(key, pkt_id, from_id, d.SerializeToString())
    flags = (hop_limit & 7) | ((1 if want_ack else 0) << 3) | ((hop_limit & 7) << 5)
    hdr = struct.pack('<IIIBBBB', to_id & 0xFFFFFFFF, from_id & 0xFFFFFFFF, pkt_id, flags, channel_hash(channel, key), 0, 0)
    return hdr + enc, pkt_id

PORT_NAMES = {v.number: v.name for v in portnums_pb2.PortNum.DESCRIPTOR.values}

def parse_packet(pkt, key):
    """returns dict with header fields and decoded content (best effort)."""
    if len(pkt) < 16:
        return None
    to, frm, pid, flags, chash, nexthop, relay = struct.unpack('<IIIBBBB', pkt[:16])
    r = dict(to=to, frm=frm, id=pid, hop_limit=flags & 7, want_ack=bool(flags >> 3 & 1), via_mqtt=bool(flags >> 4 & 1),
             hop_start=flags >> 5, chash=chash, raw=pkt)
    body = pkt[16:]
    try:
        plain = mesh_crypt(key, pid, frm, body) if key else body
        d = mesh_pb2.Data(); d.ParseFromString(plain)
        if d.portnum == 0 and not d.payload:
            raise ValueError
        r['portnum'] = d.portnum; r['port'] = PORT_NAMES.get(d.portnum, str(d.portnum))
        r['request_id'] = d.request_id; r['payload'] = d.payload
        if d.portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
            r['text'] = d.payload.decode('utf-8', 'replace')
        elif d.portnum == portnums_pb2.PortNum.NODEINFO_APP:
            u = mesh_pb2.User(); u.ParseFromString(d.payload); r['user'] = u
        elif d.portnum == portnums_pb2.PortNum.POSITION_APP:
            p = mesh_pb2.Position(); p.ParseFromString(d.payload); r['position'] = p
        elif d.portnum == portnums_pb2.PortNum.TELEMETRY_APP:
            t = telemetry_pb2.Telemetry(); t.ParseFromString(d.payload); r['telemetry'] = t
        elif d.portnum == portnums_pb2.PortNum.ROUTING_APP:
            rt = mesh_pb2.Routing(); rt.ParseFromString(d.payload); r['routing'] = rt
    except Exception:
        r['undecodable'] = True
    return r

def node_str(nid, names):
    s = f"!{nid:08x}"
    if nid == 0xFFFFFFFF: return "broadcast"
    if nid in names: return f"{names[nid]} ({s})"
    return s

def describe(r, names, my_ids):
    hops = r['hop_start'] - r['hop_limit'] if r['hop_start'] else 0
    src = node_str(r['frm'], names); dst = node_str(r['to'], names)
    meta = f"[{src} -> {dst}, id {r['id']:08x}, {hops} hop{'s' if hops != 1 else ''}]"
    if r.get('undecodable'):
        return f"{meta} (encrypted/unknown, {len(r['raw'])-16} B)"
    port = r.get('port', '?')
    if 'text' in r:
        return f"{meta} TEXT: {r['text']}"
    if 'user' in r:
        u = r['user']; names[r['frm']] = u.short_name or u.long_name
        return f"{meta} NODEINFO: {u.long_name} '{u.short_name}' id={u.id} hw={mesh_pb2.HardwareModel.Name(u.hw_model) if u.hw_model else '?'}"
    if 'position' in r:
        p = r['position']
        return f"{meta} POSITION: lat={p.latitude_i/1e7:.5f} lon={p.longitude_i/1e7:.5f} alt={p.altitude}"
    if 'telemetry' in r:
        t = r['telemetry']
        if t.HasField('device_metrics'):
            dm = t.device_metrics
            return f"{meta} TELEMETRY: batt={dm.battery_level}% V={dm.voltage:.2f} chUtil={dm.channel_utilization:.1f}% airTx={dm.air_util_tx:.1f}%"
        return f"{meta} TELEMETRY"
    if 'routing' in r:
        rt = r['routing']; rid = r.get('request_id', 0)
        err = mesh_pb2.Routing.Error.Name(rt.error_reason) if rt.error_reason else "NONE"
        mine = " (ACK for YOUR message!)" if rid in my_ids else ""
        return f"{meta} ROUTING/ACK for {rid:08x}: {err}{mine}"
    return f"{meta} {port}: {r.get('payload', b'').hex()}"

# ============================================================ RX front end: 2 MS/s int8 -> 500 kS/s complex, LO-offset removal
class FrontEnd:
    def __init__(self, lo_offset_hz):
        self.lo_offset = lo_offset_hz
        taps = 63
        cutoff = 0.16  # fraction of 2 MS/s -> 320 kHz (passband to ±125 kHz, DC spike at +200 kHz attenuated)
        k = np.arange(taps) - (taps - 1) / 2
        h = np.sinc(2 * cutoff * k) * np.hamming(taps)
        self.h = (h / h.sum()).astype(np.complex64)
        self.tail = np.zeros(taps - 1, np.complex64)
        self.phase_n = 0

    def process(self, raw: bytes):
        x = np.frombuffer(raw, dtype=np.int8).astype(np.float32) / 128.0
        z = x[0::2] + 1j * x[1::2]
        if self.lo_offset:
            n = np.arange(self.phase_n, self.phase_n + len(z))
            z = z * np.exp(2j * np.pi * self.lo_offset / HACKRF_RATE * n).astype(np.complex64)
            self.phase_n = (self.phase_n + len(z)) % (HACKRF_RATE * 1000)
        z = z.astype(np.complex64)
        y = np.convolve(np.concatenate([self.tail, z]), self.h, mode='valid')
        self.tail = z[-(len(self.h) - 1):]
        return y[::DECIM]

# ============================================================ HackRF via libhackrf (SDRangel's bundled dll)
class HackRF:
    class Transfer(ctypes.Structure):
        _fields_ = [("device", ctypes.c_void_p), ("buffer", ctypes.POINTER(ctypes.c_uint8)),
                    ("buffer_length", ctypes.c_int), ("valid_length", ctypes.c_int),
                    ("rx_ctx", ctypes.c_void_p), ("tx_ctx", ctypes.c_void_p)]
    CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(Transfer))

    def __init__(self, dll_dir=None):
        """Loads libhackrf. Search order: --dll-dir / HACKRF_DLL_DIR env, SDRangel's bundled copy, then the system PATH.
        Any libhackrf build works (hackrf-tools zip from greatscottgadgets, PothosSDR, SDRangel, or libhackrf.so on Linux)."""
        candidates = []
        if dll_dir: candidates.append(dll_dir)
        if os.environ.get("HACKRF_DLL_DIR"): candidates.append(os.environ["HACKRF_DLL_DIR"])
        candidates += [r"C:\Program Files\SDRangel", r"C:\Program Files\PothosSDRin"]
        d = None
        for cdir in candidates:
            for name in ("hackrf.dll", "libhackrf.dll"):
                p = os.path.join(cdir, name)
                if os.path.isfile(p):
                    try:
                        if hasattr(os, "add_dll_directory"): os.add_dll_directory(cdir)
                        d = ctypes.CDLL(p); break
                    except OSError: pass
            if d: break
        if d is None:
            for name in ("hackrf.dll", "libhackrf.dll", "libhackrf.so.0", "libhackrf.so", "libhackrf.dylib"):
                try: d = ctypes.CDLL(name); break
                except OSError: pass
        if d is None:
            raise RuntimeError("libhackrf not found: pass --dll-dir, set HACKRF_DLL_DIR, or install hackrf-tools")
        self.d = d
        cv, ci, cu8, cu64, cd = ctypes.c_void_p, ctypes.c_int, ctypes.c_uint8, ctypes.c_uint64, ctypes.c_double
        for name, a, r in [("hackrf_init", [], ci), ("hackrf_exit", [], ci), ("hackrf_open", [ctypes.POINTER(cv)], ci),
                           ("hackrf_set_freq", [cv, cu64], ci), ("hackrf_set_sample_rate", [cv, cd], ci),
                           ("hackrf_set_baseband_filter_bandwidth", [cv, ctypes.c_uint32], ci),
                           ("hackrf_set_lna_gain", [cv, ctypes.c_uint32], ci), ("hackrf_set_vga_gain", [cv, ctypes.c_uint32], ci),
                           ("hackrf_set_txvga_gain", [cv, ctypes.c_uint32], ci), ("hackrf_set_amp_enable", [cv, cu8], ci),
                           ("hackrf_start_rx", [cv, self.CB, cv], ci), ("hackrf_stop_rx", [cv], ci),
                           ("hackrf_start_tx", [cv, self.CB, cv], ci), ("hackrf_stop_tx", [cv], ci),
                           ("hackrf_close", [cv], ci), ("hackrf_error_name", [ci], ctypes.c_char_p)]:
            f = getattr(d, name); f.argtypes = a; f.restype = r
        self.dev = cv()
        self.rxq = queue.Queue(maxsize=200)
        self._rx_cb = self.CB(self._on_rx)
        self._tx_cb = self.CB(self._on_tx)
        self.tx = {"data": b"", "pos": 0, "done": True}

    def chk(self, name, r):
        if r != 0:
            raise RuntimeError(f"{name}: {r} ({self.d.hackrf_error_name(r).decode()})")

    def open(self, lna, vga, txvga):
        self.chk("init", self.d.hackrf_init())
        self.chk("open", self.d.hackrf_open(ctypes.byref(self.dev)))
        self.chk("rate", self.d.hackrf_set_sample_rate(self.dev, float(HACKRF_RATE)))
        self.chk("bbf", self.d.hackrf_set_baseband_filter_bandwidth(self.dev, 1_750_000))
        self.chk("freq", self.d.hackrf_set_freq(self.dev, FREQ_HZ + LO_OFFSET_HZ))
        self.chk("amp", self.d.hackrf_set_amp_enable(self.dev, 0))
        self.chk("lna", self.d.hackrf_set_lna_gain(self.dev, lna))
        self.chk("vga", self.d.hackrf_set_vga_gain(self.dev, vga))
        self.chk("txvga", self.d.hackrf_set_txvga_gain(self.dev, txvga))

    def _on_rx(self, t):
        tr = t.contents
        try:
            self.rxq.put_nowait(ctypes.string_at(tr.buffer, tr.valid_length))
        except queue.Full:
            pass
        return 0

    def _on_tx(self, t):
        tr = t.contents; n = tr.valid_length; st = self.tx
        chunk = st["data"][st["pos"]: st["pos"] + n]
        if chunk:
            ctypes.memmove(tr.buffer, chunk, len(chunk))
        if len(chunk) < n:
            ctypes.memset(ctypes.cast(ctypes.addressof(tr.buffer.contents) + len(chunk), ctypes.c_void_p), 0, n - len(chunk))
        st["pos"] += len(chunk)
        if st["pos"] >= len(st["data"]):
            st["done"] = True
        return 0

    def start_rx(self):
        while not self.rxq.empty():
            try: self.rxq.get_nowait()
            except queue.Empty: break
        self.chk("start_rx", self.d.hackrf_start_rx(self.dev, self._rx_cb, None))

    def stop_rx(self):
        self.chk("stop_rx", self.d.hackrf_stop_rx(self.dev))

    def transmit(self, iq8: bytes):
        self.tx = {"data": iq8, "pos": 0, "done": False}
        self.chk("start_tx", self.d.hackrf_start_tx(self.dev, self._tx_cb, None))
        t0 = time.time()
        while not self.tx["done"] and time.time() - t0 < 10:
            time.sleep(0.02)
        time.sleep(0.25)
        self.chk("stop_tx", self.d.hackrf_stop_tx(self.dev))

    def close(self):
        try: self.d.hackrf_close(self.dev)
        finally: self.d.hackrf_exit()

# ============================================================ TX helpers
def make_tx_iq8(pkt: bytes, lead_ms=20, tail_ms=10):
    syms = lora_encode(pkt)
    bb = lora_modulate(syms, TX_OS)
    if LO_OFFSET_HZ:
        n = np.arange(len(bb))
        bb = bb * np.exp(-2j * np.pi * LO_OFFSET_HZ / HACKRF_RATE * n)
    lead = np.zeros(int(HACKRF_RATE * lead_ms / 1000), np.complex64)
    tail = np.zeros(int(HACKRF_RATE * tail_ms / 1000), np.complex64)
    sig = np.concatenate([lead, bb.astype(np.complex64), tail])
    iq = np.empty(2 * len(sig), np.int8)
    iq[0::2] = np.clip(np.round(sig.real * 110), -127, 127).astype(np.int8)
    iq[1::2] = np.clip(np.round(sig.imag * 110), -127, 127).astype(np.int8)
    return iq.tobytes(), len(bb) / HACKRF_RATE

def write_sdriq(path, bb_complex, sample_rate, center_freq):
    hdr = struct.pack('<IQQIII', sample_rate, center_freq, int(time.time() * 1000), 16, 0, 0)
    x = np.empty(2 * len(bb_complex), np.int16)
    x[0::2] = np.clip(np.round(bb_complex.real * 30000), -32767, 32767)
    x[1::2] = np.clip(np.round(bb_complex.imag * 30000), -32767, 32767)
    with open(path, 'wb') as f:
        f.write(hdr); f.write(x.tobytes())

def read_sdriq(path, max_seconds=None):
    with open(path, 'rb') as f:
        hdr = f.read(32); sr, cf, ts, ss, fill, crc = struct.unpack('<IQQIII', hdr)
        nbytes = None if max_seconds is None else int(max_seconds * sr) * 4
        raw = f.read() if nbytes is None else f.read(nbytes)
    x = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
    return (x[0::2] + 1j * x[1::2]).astype(np.complex64), sr, cf

# ============================================================ modes
def run_selftest(args):
    key = resolve_key(args.key)
    pkt, pid = build_packet(args.from_id, 0xFFFFFFFF, portnums_pb2.PortNum.TEXT_MESSAGE_APP, b"selftest hello", key, want_ack=True, pkt_id=0x12345678)
    print(f"packet {len(pkt)} B: {pkt.hex()}")
    syms = lora_encode(pkt); print(f"{len(syms)} symbols")
    bb = lora_modulate(syms, TX_OS).astype(np.complex64)
    rng = np.random.default_rng(1)
    ok_all = True
    for ppm in [float(v) for v in args.selftest_ppm.split(",")]:
        # realistic crystal offset: the TX clock is off by `ppm` -> CFO = ppm*fc AND the waveform is time-scaled
        delta = ppm * 1e-6
        cfo_hz = delta * FREQ_HZ
        m = np.arange(int(len(bb) / (1 + delta)) - 2)
        pos = m * (1 + delta)
        sig = (np.interp(pos, np.arange(len(bb)), bb.real) + 1j * np.interp(pos, np.arange(len(bb)), bb.imag))
        sig = sig * np.exp(2j * np.pi * cfo_hz / HACKRF_RATE * m)
        delay = 12345
        noise_amp = 10 ** (-args.selftest_snr / 20)
        stream = np.concatenate([np.zeros(delay, np.complex64), sig, np.zeros(HACKRF_RATE, np.complex64)])
        stream = (stream + noise_amp * (rng.standard_normal(len(stream)) + 1j * rng.standard_normal(len(stream)))).astype(np.complex64)
        iq = np.empty(2 * len(stream), np.int8)
        iq[0::2] = np.clip(np.round(stream.real * 100), -127, 127); iq[1::2] = np.clip(np.round(stream.imag * 100), -127, 127)
        fe = FrontEnd(0); rx = LoRaRx(verbose=args.verbose)
        frames = []
        raw = iq.tobytes(); step = 262144
        for i in range(0, len(raw), step):
            frames += rx.feed(fe.process(raw[i:i + step]))
        ok = bool(frames) and frames[0][0] == pkt and frames[0][1]['crc_ok']
        ok_all &= ok
        info = frames[0][1] if frames else {}
        print(f"ppm={ppm:+5.1f} (cfo {cfo_hz:+6.0f} Hz): frames={len(frames)} "
              + (f"cfo_est={info['cfo_hz']:+.0f}Hz crc_ok={info['crc_ok']} match={frames[0][0]==pkt} netid={info['netid']}" if frames else "")
              + ("  PASS" if ok else "  FAIL"))
        if frames and ok:
            r = parse_packet(frames[0][0], key); print("   " + describe(r, {}, {pid}))
    return 0 if ok_all else 1

def run_decode_file(args):
    key = resolve_key(args.key)
    x, sr, cf = read_sdriq(args.decode_file, max_seconds=args.max_seconds)
    print(f"{args.decode_file}: {len(x)} samples @ {sr} S/s, header centerFreq={cf}")
    assert sr == HACKRF_RATE, "expected a 2 MS/s file"
    fe = FrontEnd(args.file_offset_hz); rx = LoRaRx(verbose=True)
    iq = np.empty(2 * len(x), np.int8)
    iq[0::2] = np.clip(np.round(x.real * 127), -127, 127); iq[1::2] = np.clip(np.round(x.imag * 127), -127, 127)
    raw = iq.tobytes(); frames = []; step = 262144
    for i in range(0, len(raw), step):
        frames += rx.feed(fe.process(raw[i:i + step]))
    print(f"decoded {len(frames)} frame(s)")
    names = {}
    for data, info in frames:
        print(f"  cfo={info['cfo_hz']:.0f} Hz sto={info['sto']:.2f} crc_ok={info['crc_ok']} len={info['len']} netid={info['netid']}")
        print(f"  raw: {data.hex()}")
        r = parse_packet(data, key)
        print("  " + describe(r, names, set()))
    return 0 if frames else 1

def run_encode_file(args):
    key = resolve_key(args.key)
    pkt, pid = build_packet(args.from_id, 0xFFFFFFFF, portnums_pb2.PortNum.TEXT_MESSAGE_APP, args.text.encode(), key, want_ack=args.ack)
    bb = lora_modulate(lora_encode(pkt), TX_OS)
    if args.file_shift_hz:
        bb = bb * np.exp(2j * np.pi * args.file_shift_hz / HACKRF_RATE * np.arange(len(bb)))
    sig = np.concatenate([np.zeros(HACKRF_RATE // 2, np.complex64), (bb * 0.9).astype(np.complex64), np.zeros(HACKRF_RATE // 2, np.complex64)])
    write_sdriq(args.encode_file, sig, HACKRF_RATE, FREQ_HZ)
    print(f"wrote {args.encode_file}: packet id {pid:08x}, {len(pkt)} B, {len(bb)/HACKRF_RATE:.3f}s burst (baseband-centered, 2 MS/s)")
    return 0

def run_once(args):
    """non-interactive: (optionally) send one text, then listen for --listen seconds and print decoded frames."""
    key = resolve_key(args.key); names = {}; my_ids = set()
    hack = HackRF(args.dll_dir); hack.open(args.lna, args.vga, args.gain)
    fe = FrontEnd(LO_OFFSET_HZ); rx = LoRaRx(verbose=args.verbose)
    try:
        hack.start_rx(); time.sleep(0.5)          # settle
        if args.send:
            hack.stop_rx()
            pkt, pid = build_packet(args.from_id, 0xFFFFFFFF, portnums_pb2.PortNum.TEXT_MESSAGE_APP, args.send.encode(), key, want_ack=args.ack)
            my_ids.add(pid)
            iq8, dur = make_tx_iq8(pkt)
            t0 = time.time(); hack.transmit(iq8); t1 = time.time()
            print(f"{time.strftime('%H:%M:%S')} TX id {pid:08x} ({len(pkt)} B, {dur:.2f}s on air, {t1-t0:.2f}s wall){' want_ack' if args.ack else ''}", flush=True)
            hack.start_rx()
        t_end = time.time() + args.listen; nbuf = 0; pwr = []
        print(f"listening {args.listen:.0f}s on {FREQ_HZ/1e6:.3f} MHz ...", flush=True)
        while time.time() < t_end:
            try: raw = hack.rxq.get(timeout=0.2)
            except queue.Empty: continue
            nbuf += 1
            y = fe.process(raw)
            if nbuf % 15 == 0: pwr.append(10*np.log10(np.mean(np.abs(y)**2) + 1e-12))
            for data, info in rx.feed(y):
                r = parse_packet(data, key)
                print(f"{time.strftime('%H:%M:%S')} RX crc_ok={info['crc_ok']} cfo={info['cfo_hz']:+.0f}Hz " + (describe(r, names, my_ids) if r else data.hex()), flush=True)
        print(f"done: {nbuf} buffers, baseband power {np.mean(pwr):.1f} dBFS (noise floor), queue backlog {hack.rxq.qsize()}", flush=True)
    finally:
        try: hack.stop_rx()
        except Exception: pass
        hack.close()
    return 0

def run_chat(args):
    key = resolve_key(args.key)
    names = {}; my_ids = set()
    want_ack = args.ack; to_id = 0xFFFFFFFF; show_hex = False
    hack = HackRF(args.dll_dir)
    hack.open(args.lna, args.vga, args.gain)
    fe = FrontEnd(LO_OFFSET_HZ); rx = LoRaRx(verbose=args.verbose)
    lock = threading.Lock()
    tx_request = queue.Queue()
    stop = threading.Event()

    def rx_worker():
        while not stop.is_set():
            try:
                raw = hack.rxq.get(timeout=0.2)
            except queue.Empty:
                continue
            with lock:
                for data, info in rx.feed(fe.process(raw)):
                    r = parse_packet(data, key)
                    t = time.strftime('%H:%M:%S')
                    if r is None:
                        print(f"\n{t} [frame {len(data)} B, crc_ok={info['crc_ok']}] {data.hex()}"); continue
                    flag = "" if info['crc_ok'] else " (CRC FAIL)"
                    print(f"\n{t} RX{flag} cfo={info['cfo_hz']:+.0f}Hz " + describe(r, names, my_ids))
                    if show_hex: print(f"   hex: {data.hex()}")
                    print("> ", end="", flush=True)

    def send(pkt, secs):
        with lock:
            hack.stop_rx()
            iq8, dur = make_tx_iq8(pkt)
            hack.transmit(iq8)
            hack.start_rx()
            fe.tail[:] = 0
        return dur

    print(f"meshchat: node !{args.from_id:08x} '{args.name}' on {FREQ_HZ/1e6:.3f} MHz LongFast, key={args.key}, want_ack={want_ack}")
    print("type a message and Enter to send; /ack on|off, /to !id|all, /nodeinfo, /hex, /quit")
    hack.start_rx()
    th = threading.Thread(target=rx_worker, daemon=True); th.start()
    try:
        while True:
            try:
                line = input("> ")
            except EOFError:
                break
            line = line.strip()
            if not line: continue
            if line == "/quit": break
            if line.startswith("/ack"):
                want_ack = line.endswith("on"); print(f"want_ack={want_ack}"); continue
            if line.startswith("/to"):
                arg = line[3:].strip()
                to_id = 0xFFFFFFFF if arg in ("all", "") else int(arg.lstrip("!"), 16); print(f"to={node_str(to_id, names)}"); continue
            if line == "/hex":
                show_hex = not show_hex; print(f"show_hex={show_hex}"); continue
            if line == "/nodeinfo":
                u = mesh_pb2.User(id=f"!{args.from_id:08x}", long_name=args.name, short_name=args.short,
                                  hw_model=mesh_pb2.HardwareModel.PRIVATE_HW)
                pkt, pid = build_packet(args.from_id, 0xFFFFFFFF, portnums_pb2.PortNum.NODEINFO_APP, u.SerializeToString(), key, want_ack=False)
                dur = send(pkt, None); print(f"sent NODEINFO id {pid:08x} ({dur:.2f}s on air)"); continue
            pkt, pid = build_packet(args.from_id, to_id, portnums_pb2.PortNum.TEXT_MESSAGE_APP, line.encode(), key, want_ack=want_ack)
            my_ids.add(pid)
            dur = send(pkt, None)
            print(f"{time.strftime('%H:%M:%S')} TX id {pid:08x} -> {node_str(to_id, names)} ({len(pkt)} B, {dur:.2f}s on air){' want_ack' if want_ack else ''}")
    finally:
        stop.set()
        try: hack.stop_rx()
        except Exception: pass
        hack.close()
        print("bye")
    return 0

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="from_id", type=lambda s: int(s, 0), default=0xA1B2C3D4)
    ap.add_argument("--name", default="HackRF Pro"); ap.add_argument("--short", default="HKRF")
    ap.add_argument("--key", default="default")
    ap.add_argument("--ack", action="store_true", help="request ACK for text messages")
    ap.add_argument("--gain", type=int, default=30, help="TX VGA 0..47"); ap.add_argument("--lna", type=int, default=32); ap.add_argument("--vga", type=int, default=20)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--dll-dir", default=None, help="directory containing hackrf.dll / libhackrf (default: HACKRF_DLL_DIR env, SDRangel, PATH)")
    ap.add_argument("--send", help="non-interactive: send this text once"); ap.add_argument("--listen", type=float, default=0.0, help="non-interactive: listen this many seconds")
    ap.add_argument("--selftest", action="store_true"); ap.add_argument("--selftest-ppm", default="0,4,-6,10"); ap.add_argument("--selftest-snr", type=float, default=20.0)
    ap.add_argument("--decode-file"); ap.add_argument("--file-offset-hz", type=float, default=0.0); ap.add_argument("--max-seconds", type=float, default=None)
    ap.add_argument("--encode-file"); ap.add_argument("--file-shift-hz", type=float, default=0.0); ap.add_argument("text", nargs="?", default="Hei fra HackRF Pro")
    args = ap.parse_args()
    if args.selftest: return run_selftest(args)
    if args.send or args.listen: return run_once(args)
    if args.decode_file: return run_decode_file(args)
    if args.encode_file: return run_encode_file(args)
    return run_chat(args)

if __name__ == "__main__":
    sys.exit(main())
