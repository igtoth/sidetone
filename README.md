<p align="center">
  <img src="assets/icon/sidetone-256.png" alt="Sidetone" width="120">
</p>

<h1 align="center">Sidetone</h1>

<p align="center">
  <b>A SIP softphone built for troubleshooting: place the call, see the ladder, and know why it failed.</b><br>
  Test calls over UDP, TCP, TLS or WebRTC, SRTP included, pcap and pcapng analysis, RTP quality and MOS, plain-language diagnostics,<br>
  an AI second opinion with your own keys, automated test suites and an MCP server, for Windows, macOS, Linux and the browser.
</p>

<p align="center">
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-b7410e?style=flat-square&logo=rust">
  <img alt="Windows, macOS, Linux and the browser" src="https://img.shields.io/badge/Windows%20%C2%B7%20macOS%20%C2%B7%20Linux%20%C2%B7%20Web-native-1f6fc5?style=flat-square">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-444444?style=flat-square">
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-d97706?style=flat-square">
  <img alt="MCP server" src="https://img.shields.io/badge/MCP-server-7b5cff?style=flat-square">
  <a href="https://github.com/igtoth/sidetone/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/igtoth/sidetone/ci.yml?branch=main&style=flat-square&label=CI"></a>
</p>

<p align="center">
  <a href="#downloads"><b>Download</b></a> &middot;
  <a href="https://igtoth.github.io/sidetone/">Open it in the browser</a> &middot;
  <a href="examples/">Test suite examples</a> &middot;
  <a href="#help-wanted">Contribute</a>
</p>

<p align="center">
  <sub>Alpha: expect rough edges. A capture that Sidetone reads wrong or a finding that misleads? <a href="https://github.com/igtoth/sidetone/issues/new">Open an issue</a> with a redacted pcapng (Export &rsaquo; Redacted pcapng): real traces are what improve the rules most.</sub>
</p>

<br>

<p align="center">
  <img src="docs/images/sidetone-phone.jpg" alt="Sidetone on the desktop: the phone panel on the left with account Lab 2001 registered, the toolbar with Conference active, the keypad, BLF lamps showing 3001 busy and 5001 free, and three connected lines, two of them joined in a conference; on the right the current call with Opus as codec, media addresses and RTP counters, the phone event log ending in conference: lines 4 and 6 joined, and the call history with 404 and 486 results" width="100%">
  <br>
  <sub>Three lines, two of them in a local conference, Opus on the wire, BLF lamps, every event and result in plain words.</sub>
</p>

<p align="center">
  <a href="#features">Features</a> &middot;
  <a href="#everything-in-the-box">Everything in the box</a> &middot;
  <a href="#made-to-be-automated">Automation</a> &middot;
  <a href="#ai-with-your-own-keys">AI</a> &middot;
  <a href="#under-the-hood">Under the hood</a> &middot;
  <a href="#get-started">Get started</a> &middot;
  <a href="#help-wanted">Help wanted</a> &middot;
  <a href="#downloads">Downloads</a>
</p>

<br>

<table>
  <tr>
    <td width="25%" valign="top">
      <h3>A real softphone</h3>
      Several accounts and lines, hold, mute, blind and attended transfer, DTMF three ways, DND and auto answer, call forwarding, a voicemail lamp, SIP MESSAGE, microphone and speaker. SIP over UDP, TCP or TLS from the desktop, with SDES or DTLS-SRTP, or over WebSocket with WebRTC from the browser.
    </td>
    <td width="25%" valign="top">
      <h3>It explains the call</h3>
      Around 40 deterministic rules read signaling and media and say what went wrong in words: missing ACK, NAT in SDP, one-way audio, codec mismatch, loss and jitter, with the message numbers as evidence.
    </td>
    <td width="25%" valign="top">
      <h3>Evidence you can share</h3>
      Annotated pcapng with findings as Wireshark packet comments, TLS keys embedded when available, and a redacted export that masks numbers, names, credentials and public IPs.
    </td>
    <td width="25%" valign="top">
      <h3>Built for troubleshooting</h3>
      A live SIP trace, every packet captured without a driver, DNS SRV and NAT checks, and a CLI, JSON test suites and an MCP server so scripts and AI agents can do the same.
    </td>
  </tr>
</table>

<br>

## Features

Every screenshot is Sidetone itself, captured headless by
`scripts/readme-shots.mjs` against the throwaway PBX in `lab/` and the
built-in sample captures, with a test tone instead of a microphone. Some
are in the dark theme (the Theme button, or your system setting).

<table>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-trace-live.jpg" alt="Dark theme: the SIP trace page with a live list of messages (time, direction, address, first line coloured by result, Call-ID), filters to hide REGISTER and OPTIONS, Pause, Clear, Save pcapng and Analyze capture, and the selected INVITE shown in full below" width="100%">
      <br>
      <sub>The live SIP trace: every request and response as it happens.</sub>
      <h3>See the wire while you talk</h3>
      Each message the phone sends or receives appears at once with its time, direction and peer; responses are coloured by class. Filter by number, method or Call-ID, hide the REGISTER and OPTIONS noise, pause, save the session as pcapng, or open it in the analyzer with one click.
    </td>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-hero.jpg" alt="The analysis view of a capture with seven calls: the dialogs list on the left, the ladder of a NAT call with ten retransmitted 200 OK responses marked in red, and the Findings tab listing 200 OK retransmitted, No ACK and Call ended 32 s after answer" width="100%">
      <br>
      <sub>A remote worker behind NAT: 200 OK retransmitted ten times, no ACK, drop at 32 s.</sub>
      <h3>The ladder, with the diagnosis on it</h3>
      Calls you make are captured and analyzed with the same engine as any pcap or pcapng from Wireshark, tcpdump, sngrep or an SBC. Dialogs are grouped by Call-ID; the ladder marks retransmissions and colours each response class; a dot shows which messages a finding points to.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-message.jpg" alt="Dark theme: the INVITE selected in the ladder and, below, the two findings it triggered (private Contact and private SDP address) above the full SIP message with coloured header names" width="100%">
      <br>
      <sub>The INVITE that started it: private Contact and private SDP address.</sub>
      <h3>About 40 rules that explain the call</h3>
      Missing ACK, NAT in SDP, one-way audio, codec mismatch, failed authentication, glare, session timer expiry, loss and jitter: each finding says what happened in words, with the message numbers as evidence.
    </td>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-media.jpg" alt="The Media tab for a call with two PCMU streams: packets, lost, loss 13.40 and 15.00 percent in red, jitter 46.4 ms, max gap 1513 ms and MOS estimates of 2.92 and 2.90" width="100%">
      <br>
      <sub>Both directions of a bad call: loss, jitter, a 1.5 s gap and MOS below 3.</sub>
      <h3>Media you can measure</h3>
      Each RTP stream is tied to its call through the SDP: codec, packets, loss, RFC 3550 jitter, the longest gap, ptime, RFC 4733 digits and an ITU-T G.107 E-model MOS estimate. Per-second charts show jitter, loss and MOS over the call with the SIP events marked; RTCP sender and receiver reports (RFC 3550), RTCP XR VoIP metrics (RFC 3611) and vq-rtcpxr PUBLISH reports (RFC 6035) add what the far end measured, including round trip time; G.711 streams also get level, silence and clipping. Calls of the same session on both sides of an SBC or B2BUA are linked by X-CID, Session-ID and similar headers. MOS is also worked out through a fixed 50 ms, a fixed 200 ms and an adaptive jitter buffer, where a packet that arrives too late counts as lost. HEP (Homer) packets in a capture are unwrapped, the phone can send a HEPv3 copy of every SIP message to a Homer collector, and SRTP calls can be saved with the media decrypted. The ladder can show time since the start, since the row above or as clock time, and fold retransmissions into the arrow they repeat.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-settings.jpg" alt="Account settings on the Media tab: codecs in order of preference with Opus, PCMU and PCMA ticked, SRTP media encryption set to Optional, packet time and offered direction, and tabs for Account, Server and registration, Network, Media, DTMF, Advanced SIP, Headers and BLF" width="100%">
      <br>
      <sub>Per-account media: Opus and G.711 in your order, SRTP off, optional or required, with SDES or DTLS-SRTP keys.</sub>
      <h3>Every knob a desk phone has, and a preview</h3>
      Per account: UDP, TCP or TLS, outbound proxy, expiry and retry, keepalives, local IP and port, rport, symmetric RTP, RTP ports, DSCP, SDP address override, T1, codec order (Opus, PCMU, PCMA), SRTP, ptime, DTMF mode and payload type, session timers, <code>user=phone</code>, compact headers, PRACK, GRUU, long Contact, extra headers, BLF extensions, and a preview of the INVITE they produce. Some exist to reproduce a broken client on purpose, like skipping the ACK.
    </td>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-diag.jpg" alt="Dark theme: the Diagnostics page with an OPTIONS ping answered 200 OK in 4 ms by Asterisk, a DNS lookup showing where UDP requests go, the NAT card with STUN servers and what the SIP server sees for each account, and the Audio card with microphone and speaker choice, level meters and a loopback test" width="100%">
      <br>
      <sub>Reachability, DNS, NAT and audio checks in one place.</sub>
      <h3>Diagnostics before the call</h3>
      OPTIONS ping with round trip and server agent, RFC 3263 lookups (NAPTR, SRV for UDP, TCP and TLS, A/AAAA), STUN against two servers to spot a symmetric NAT, the address each registrar sees you from, a microphone and speaker test with level meters, and a live capture on any network interface for traffic that is not the phone's own.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-ai.jpg" alt="Dark theme: a capture with one NAT call in Analysis, the ladder with retransmitted 200 OK responses, and the Ask AI tab showing the provider and model from Settings, a masking checkbox ticked, a question about a remote worker, and the masked prompt preview" width="100%">
      <br>
      <sub>Ask AI, with "Show what will be sent" before anything leaves.</sub>
      <h3>An AI second opinion</h3>
      An AI panel docked under any page lets you hold a conversation about the selected call, the live trace or a capture: the model gets the findings, the ladder, the RTP statistics and the relevant raw messages, masked by default. Configure it once in Settings, AI: Anthropic, any OpenAI-compatible service (OpenAI, Gemini, OpenRouter, Groq, Mistral, DeepSeek, LM Studio, vLLM) or a local Ollama, with a connection test.
    </td>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-webrtc.jpg" alt="The browser version registered over WebSocket as 4001, a call to 600 connected with Opus over DTLS-SRTP, live packet counters and the ICE path, the phone events and DTMF sent as RFC 4733" width="100%">
      <br>
      <sub>No install: the browser version on GitHub Pages, calling over WebRTC.</sub>
      <h3>The same phone in the browser</h3>
      On GitHub Pages Sidetone talks SIP over WebSocket (RFC 7118) with WebRTC audio, so it reaches any PBX or SBC with a WSS listener. Several lines with automatic hold and call waiting, mute, blind and attended transfer, a three-way conference mixed with Web Audio, and DTMF; analysis runs in the page through WebAssembly.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <img src="docs/images/sidetone-help.jpg" alt="The interface in Portuguese (Brazil): the Help page with sections on getting started, making calls, hold and transfer, and TCP, TLS, SRTP, BLF and conference, and the language selector" width="100%">
      <br>
      <sub>The interface and the built-in help in Portuguese.</sub>
      <h3>Your language, with help built in</h3>
      English, Portuguese (Brazil), Spanish, German, French, Chinese (Simplified) and Hindi, switched in Settings or on the Help page. Findings and explanations are translated too; SIP messages and traces stay as they were on the wire, so what you paste into a ticket reads the same for everyone. Help covers accounts, calls, transfers, TCP/TLS, SRTP, BLF, conference, analysis and common problems.
    </td>
    <td width="50%" valign="top">
    </td>
  </tr>
</table>

<br>

## Everything in the box

<table>
  <tr>
    <td width="33%" valign="top">
      <h4>About 40 diagnostic rules</h4>
      INVITE without response &middot; failure codes explained &middot; 200 OK retransmitted &middot; no ACK &middot; drop at 32 s &middot; session timer expiry &middot; credentials rejected &middot; challenge not answered &middot; 481 in dialog &middot; glare &middot; slow first response &middot; post-dial delay &middot; private SDP or Contact behind a public source &middot; wrong interface on an unanswered REGISTER &middot; no common codec &middot; answer with codecs not offered &middot; SRTP vs RTP &middot; missing crypto or fingerprint &middot; DTLS role conflict &middot; DTMF not negotiated &middot; ptime mismatch &middot; hold &middot; one-way audio &middot; no RTP &middot; asymmetric RTP &middot; loss &middot; jitter &middot; gaps &middot; SSRC change &middot; unnegotiated payload types &middot; low MOS &middot; far-end loss, round trip and MOS from RTCP and vq-rtcpxr &middot; phone boot provisioning (DHCP option 66/150 missing, TFTP file not found, no answer, cut off) &middot; RTP that carries only silence &middot; clipping &middot; Q.850 Reason causes &middot; missing mandatory headers &middot; Content-Length errors &middot; Max-Forwards near zero
    </td>
    <td width="33%" valign="top">
      <h4>Captures in and out</h4>
      Capture live on any network interface (libpcap or Npcap, loaded at run time) with a BPF filter, watch SIP go by, then analyze or save it.
      <br><br>
      Read: pcap and pcapng (Ethernet, VLAN, Linux cooked v1 and v2, raw IP, loopback, Wireshark exported PDUs), IPv4 and IPv6, SIP over UDP, TCP and decrypted TLS, TLS key logs from pcapng.
      <br><br>
      Search: Wireshark-style display filters over SIP and SDP (<code>ip.addr == 10.0.0.5 &amp;&amp; sip.status &gt;= 400</code>, <code>sdp.codec == PCMA</code>, <code>sip.from contains "2001"</code>) in the trace and in Analysis.
      <br><br>
      Listen: pick any RTP stream, hear it and see its waveform with a playhead (G.711 and Opus), save it as WAV.
      <br><br>
      Write: the phone's own traffic as it travelled (SIP over TCP as TCP, over TLS as decrypted exported PDUs, like Wireshark's Export PDUs); annotated pcapng with findings as packet comments and TLS keys kept; redacted pcapng for sharing; one call or the whole capture; ladder as SVG; report as JSON; stereo WAV of each test call (left sent, right received).
    </td>
    <td width="33%" valign="top">
      <h4>The phone</h4>
      Several accounts with re-registration at 90% of the expiry and retry on failure &middot; SIP over UDP, TCP and TLS (certificate check on or off per account) &middot; SRTP with SDES keys or DTLS-SRTP (certificate checked against a=fingerprint), AES_CM_128_HMAC_SHA1_80 and _32 and AEAD_AES_128/256_GCM, optional or mandatory &middot; digest auth (MD5, qop auth) &middot; several lines with automatic hold &middot; hold and resume by re-INVITE &middot; mute &middot; blind transfer (REFER) and attended transfer (REFER with Replaces), and being transferred &middot; three-way conference mixed locally &middot; BLF (SUBSCRIBE to the dialog event package) showing idle, ringing and busy, with presence (PIDF) when the server offers it, and your own presence published with PUBLISH &middot; DTMF as RFC 4733, SIP INFO or inband tones, and received digits shown &middot; DND and auto answer with the reject code you choose &middot; intercom answer (Call-Info, Alert-Info) &middot; PRACK, UPDATE, session timers, late offer &middot; ringback and ring tones &middot; per-call WAV recording &middot; DNS SRV and outbound proxy &middot; direct, unregistered calls to any SIP URI (anonymous From, for testing URI dialing) &middot; dial strings with headers and post-answer DTMF (<code>600?Subject=x,,123#</code>) &middot; 16 codecs, each tested against Asterisk: G.711 &mu;-law and A-law, G.722, Opus (16 kHz audio path, in-band FEC), G.729A, iLBC (20 and 30 ms), Speex narrowband and wideband, GSM 06.10, G.726-16/24/32/40 (RFC 3551 or AAL2 bit order), linear PCM at 8, 16 and 44.1 kHz; a global list in order of preference, a list per account and a list per call &middot; configuration import and export as one JSON file (in the app and with <code>sidetone config export|import</code>), passwords optional, also loaded from an HTTP(S) provisioning URL &middot; call forwarding (always, busy, no answer) with 302 &middot; voicemail lamp from message-summary (RFC 3842) &middot; SIP MESSAGE (RFC 3428) sent and received &middot; HEPv3 copies of every SIP message to a Homer collector &middot; live call table with duration, codec, transport, RTP counters and the result of the last action (hold, transfer or DTMF refused, unsupported or unanswered, with the reason) &middot; phone-only mode that turns the desktop window into a compact softphone &middot; interface in English, Portuguese (Brazil), Spanish, German, French, Chinese (Simplified) and Hindi, with built-in help &middot; WebRTC with Opus, ICE and DTLS-SRTP in the browser, with several lines, attended transfer and conference
    </td>
  </tr>
  <tr>
    <td width="33%" valign="top">
      <h4>Command line</h4>
      <code>analyze</code> &middot; <code>export</code> &middot; <code>ai</code> &middot; <code>call</code> &middot; <code>answer</code> &middot; <code>register</code> &middot; <code>options</code> &middot; <code>test</code> &middot; <code>test-gen</code> &middot; <code>test-format</code> &middot; <code>samples</code> &middot; <code>profile</code> &middot; <code>serve</code> &middot; <code>mcp</code>
    </td>
    <td width="33%" valign="top">
      <h4>MCP tools</h4>
      <code>analyze_capture</code> &middot; <code>get_ladder</code> &middot; <code>get_message</code> &middot; <code>get_call_context</code> &middot; <code>export_pcapng</code> &middot; <code>generate_sample</code> &middot; <code>sip_options</code> &middot; <code>test_call</code> &middot; <code>get_test_suite_format</code> &middot; <code>run_test_suite</code>
    </td>
    <td width="33%" valign="top">
      <h4>Built-in examples</h4>
      Seven synthetic captures with known problems, so every rule can be seen without real customer traffic: a clean call with DTMF, NAT with one-way audio and a 32 s drop, a 488 codec rejection, a lossy call, a REGISTER that never gets an answer, an SRTP mismatch, and all of them together.
    </td>
  </tr>
</table>

<br>

## Made to be automated

The CLI and the web app share one engine, so anything the window does, a
script does too.

```sh
# Read a capture: calls, ladder, RTP, findings
sidetone analyze trace.pcapng --ladder
sidetone analyze trace.pcapng --call 3 --svg call3.svg
sidetone analyze trace.pcapng --json > report.json

# Share it: findings as Wireshark comments, or masked for a vendor ticket
sidetone export trace.pcapng -o annotated.pcapng
sidetone export trace.pcapng -o share.pcapng --call 3 --redact

# Be a Homer collector: receive HEPv3 from Kamailio, OpenSIPS, FreeSWITCH
# or heplify, save it, and analyze it like any capture
sidetone hep --listen 0.0.0.0:9060 -o hep.pcapng

# Place calls from a script, then read what happened
sidetone call 600 --domain pbx.lab:5060 --user 2001 --password "$PW" \
  --register --dtmf 123# --pcap call.pcapng --wav call.wav
sidetone answer --domain pbx.lab --user 3001 --password "$PW" --register --audio echo
sidetone options pbx.lab
```

Test suites are JSON: cases made of `register`, `options`, `call`, `wait`
and `unregister` steps, each with expectations (final status, maximum
errors, minimum MOS, loss, jitter, post-dial delay, talk time, codec, RTP
received, rules that must or must not appear). Each case saves its pcapng.

```sh
SIP_PASSWORD=... sidetone test examples/asterisk-lab.suite.json --junit junit.xml
sidetone test suite.json --ai-explain     # failed cases get an AI explanation
sidetone test-gen "register 2001 on pbx.lab and check echo 600 with DTMF and MOS above 4" -o new.suite.json
```

```json
{ "name": "echo test with DTMF",
  "steps": [ { "call": { "target": "600", "duration": 4, "dtmf": "123#",
      "expect": { "status": 200, "min_mos": 4.0, "rtp_received": true,
                  "rules_present": ["rtp.dtmf"], "rules_absent": ["rtp.one_way"] } } } ] }
```

Serve the analyzer and the phone to an AI agent over the Model Context Protocol:

```json
{ "mcpServers": { "sidetone": { "command": "/path/to/sidetone", "args": ["mcp"] } } }
```

## AI with your own keys

Sidetone has no AI of its own and no account. Detection is deterministic;
the model is only asked to interpret, which keeps answers grounded and
cheap. Pick Anthropic, any OpenAI-compatible endpoint (a gateway, LM Studio,
vLLM) or a local Ollama; nothing is sent until you ask, masking is on by
default, and "Show what will be sent" prints the exact prompt.

```sh
export ANTHROPIC_API_KEY=...
sidetone ai trace.pcapng --call 2 --lang "Portuguese (Brazil)"
sidetone ai trace.pcapng --provider ollama --model llama3.1
sidetone ai trace.pcapng --dry-run
```

In the browser the key stays in that browser and goes only to the provider;
Ollama needs `OLLAMA_ORIGINS` to include the page origin.

## Under the hood

- **Engine first:** `crates/sidetone-core` holds capture I/O, SIP/SDP/RTP
  parsing, call correlation, the rules, the ladder, export, redaction and
  the AI prompt, with no network or audio code, so it runs natively and as
  WebAssembly.
- **One frontend, three homes:** `web/` runs on GitHub Pages with the
  analyzer in WASM, behind `sidetone serve`, and inside the Tauri desktop
  app, which starts the local server on a random loopback port protected by
  a per-launch token.
- **A phone engine, not a script:** `crates/sidetone-ua` runs one
  signaling thread with RFC 3261 client transactions and timers, dialogs,
  re-INVITE, REFER/NOTIFY and Replaces, and a media thread pair per line;
  the UI drives it through a small HTTP API and reads snapshots, events and
  the trace. Accounts, settings and history live in your user
  configuration folder (`SIDETONE_CONFIG_DIR` overrides it).
- **Capture without drivers:** the phone records its own datagrams with
  real addresses and timestamps, so no Npcap, libpcap or root is needed.
- **The interface the OS would use:** the local address comes from the
  route to the server, so a VPN or virtual adapter does not end up in Via,
  Contact and SDP.
- **Tested against a real PBX:** CI runs unit tests on Linux, Windows and
  macOS, builds the WASM, starts Asterisk from `lab/`, runs the example
  suite, drives the phone engine through calls, hold, DTMF, both kinds of
  transfer, DND and auto answer, and opens every exported capture with
  tshark.

## Get started

```sh
git clone https://github.com/igtoth/sidetone
cd sidetone
cargo run --release -p sidetone-cli -- serve      # phone and analyzer on http://127.0.0.1:8640
cargo run --release -p sidetone-cli -- samples ./samples
cargo test --workspace --exclude sidetone-desktop
```

A recent stable Rust (CI uses stable). The desktop app builds with
`npx @tauri-apps/cli@2 build` in `app/`; on Linux it needs WebKitGTK 4.1.
For a local PBX to call: `lab/run-asterisk.sh` (Asterisk on UDP, TCP, TLS
and WebSocket, with SDES and DTLS-SRTP users, a WebRTC user, BLF and presence
hints, echo, busy and unallocated numbers).

> [!IMPORTANT]
> **Status: alpha.** The analyzer, the desktop and browser phones, test
> suites and the MCP server work and are covered by tests and a live PBX
> in CI, but Sidetone is young: expect rough edges with PBXs and SBCs the
> lab does not cover, and please report them. MOS is an estimate from one
> capture point, as any single-point measurement is.

## Provisioning

Sidetone can load account settings from a small XML file served over HTTP(S).
In Settings, open an account and press **Provision**, then paste the URL.
A valid file is saved and the account registers.
Besides its own strict format, the desktop app reads the Yealink `.cfg`,
Polycom XML and Cisco `SEP<MAC>.cnf.xml` files a PBX already serves to desk
phones (the first configured line becomes the account), over HTTP, HTTPS or
TFTP, with `{mac}` in the URL filled with the device MAC. It can ask DHCP for
the server phones are given (options 66, 150, 160), Diagnostics fetches what
a phone with a given MAC would get, and Analysis explains DHCP and TFTP in a
capture of a phone booting. Every key, the vendor mappings, the samples and
the resync rules are in [docs/provisioning.md](docs/provisioning.md). To back
up or move the whole configuration instead, use Settings, Import and export
(one JSON file, from a file or a URL).

Example (`sidetone-provision` version 1; `display_name` is required):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<sidetone-provision version="1">
  <account.1.user>2001</account.1.user>
  <account.1.display_name>Lab 2001</account.1.display_name>
  <account.1.domain>pbx.example.com</account.1.domain>
  <account.1.password>secret</account.1.password>
  <account.1.transport>udp</account.1.transport>
</sidetone-provision>
```

Browser accounts also need `account.1.ws` and usually `account.1.ice`.

When the registrar sends SIP NOTIFY with `Event: check-sync` or `Event: resync`,
Sidetone re-downloads the stored provisioning URL for that account. If
**Accept requests only from the registrar** is on, check-sync applies only when
the NOTIFY comes from the registrar. A resync during a call is deferred until
that account's last call ends; if a new call starts while the file is
downloading, apply waits again. Downloads for the same account are at least
10 seconds apart, measured from the start of the last attempt.

The desktop app fetches provisioning URLs directly (it does not use
`HTTPS_PROXY`). TLS is checked against public roots unless you turn off
**Check the server's TLS certificate** in the provision dialog; the browser
phone always uses the browser's TLS rules and cannot disable verification. An
HTTPS-hosted page cannot fetch an `http://` provisioning URL (mixed content);
use the desktop app for a LAN HTTP server.

In the browser, `account.1.remember_password` set to `0` keeps the password only
until you reload the page (unless you save with remember enabled in Settings).

## Help wanted

- **Try it on your own traces.** A capture Sidetone reads wrong, or a
  finding that misleads, sent as a redacted pcapng in
  [an issue](https://github.com/igtoth/sidetone/issues/new), improves the
  rules more than anything else.
- **Write a rule.** Each rule is a few lines in
  `crates/sidetone-core/src/rules.rs` plus a synthetic scenario in
  `synth.rs` that proves it.
- **Share a test suite** for your PBX, SBC or carrier in `examples/`.
- **Package it** for the system you use (Homebrew, winget, AUR, Flatpak).

## Downloads

Each version gets a release with installers for every platform: take the
[latest release](https://github.com/igtoth/sidetone/releases/latest), or
pick a file below (version 0.1.25).

| Platform | Install | Portable (no install) | Command line (also standalone) |
|---|---|---|---|
| Windows 10/11 (x64) | [Installer (.exe)](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_0.1.25_x64-setup.exe) &middot; [MSI](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_0.1.25_x64_en-US.msi) | [Sidetone_0.1.25_x64_portable.zip](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_0.1.25_x64_portable.zip) | [sidetone-v0.1.25-x86_64-pc-windows-msvc.zip](https://github.com/igtoth/sidetone/releases/download/v0.1.25/sidetone-v0.1.25-x86_64-pc-windows-msvc.zip) |
| macOS 11+ (Apple silicon) | [Sidetone_0.1.25_aarch64.dmg](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_0.1.25_aarch64.dmg) | [Sidetone_aarch64.app.tar.gz](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_aarch64.app.tar.gz) | [sidetone-v0.1.25-aarch64-apple-darwin.tar.gz](https://github.com/igtoth/sidetone/releases/download/v0.1.25/sidetone-v0.1.25-aarch64-apple-darwin.tar.gz) |
| macOS 11+ (Intel) | [Sidetone_0.1.25_x64.dmg](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_0.1.25_x64.dmg) | [Sidetone_x64.app.tar.gz](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_x64.app.tar.gz) | [sidetone-v0.1.25-x86_64-apple-darwin.tar.gz](https://github.com/igtoth/sidetone/releases/download/v0.1.25/sidetone-v0.1.25-x86_64-apple-darwin.tar.gz) |
| Linux (x86_64) | [.deb](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_0.1.25_amd64.deb) &middot; [.rpm](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone-0.1.25-1.x86_64.rpm) | [AppImage](https://github.com/igtoth/sidetone/releases/download/v0.1.25/Sidetone_0.1.25_amd64.AppImage) | [sidetone-v0.1.25-x86_64-unknown-linux-gnu.tar.gz](https://github.com/igtoth/sidetone/releases/download/v0.1.25/sidetone-v0.1.25-x86_64-unknown-linux-gnu.tar.gz) |
| Linux (arm64) | | | [sidetone-v0.1.25-aarch64-unknown-linux-gnu.tar.gz](https://github.com/igtoth/sidetone/releases/download/v0.1.25/sidetone-v0.1.25-aarch64-unknown-linux-gnu.tar.gz) |
| Web | no download: [open it in the browser](https://igtoth.github.io/sidetone/) | | |

**Portable and standalone.** Nothing has to be installed:

- **Windows:** unzip `Sidetone_..._portable.zip` anywhere (a USB stick works) and run `Sidetone.exe`. It uses the WebView2 that comes with Windows 10 and 11.
- **macOS:** unpack `Sidetone_....app.tar.gz` and open `Sidetone.app` from any folder.
- **Linux:** `chmod +x` the AppImage and run it. On distributions without FUSE 2, run it with `--appimage-extract-and-run`.
- **Command line, any platform:** a single executable with the interface built in. Double click `sidetone` (or run it with no arguments) and the full app opens in your browser, with no WebView or system library needed. Closing its window stops it. `sidetone serve --open` does the same from a terminal.

Settings, accounts and history live in your user configuration folder in every form, so you can switch between them. To keep everything with the program instead (a USB stick, say), create a folder named `sidetone-data` next to the executable, or set `SIDETONE_CONFIG_DIR`.

### Install

**Windows.** Run the `.exe` installer (or the `.msi` for managed
deployments). The downloads are not code-signed yet: if SmartScreen warns,
choose More info &rsaquo; Run anyway. Allow Sidetone through Windows
Firewall when asked, or incoming calls cannot reach it.

**macOS.** Open the `.dmg` and drag Sidetone to Applications. The app is
not signed yet, so the first time right-click it and choose Open (or run
`xattr -dr com.apple.quarantine /Applications/Sidetone.app`). macOS asks
for microphone access on the first call.

**Linux.** Debian and Ubuntu: `sudo apt install ./Sidetone_0.1.25_amd64.deb`.
Fedora and openSUSE: `sudo dnf install ./Sidetone-0.1.25-1.x86_64.rpm`.
Anywhere else: `chmod +x Sidetone_0.1.25_amd64.AppImage` and run it. The
desktop app needs WebKitGTK 4.1 (present on current distributions).

**Command line.** Unpack the archive and put `sidetone` on your `PATH`:

```sh
tar xzf sidetone-v0.1.25-x86_64-unknown-linux-gnu.tar.gz
sudo install sidetone-v0.1.25-x86_64-unknown-linux-gnu/sidetone /usr/local/bin/
sidetone              # the full app in your browser (same as sidetone serve --open)
```

On macOS remove the quarantine flag first
(`xattr -d com.apple.quarantine sidetone`). The archive also has the
example test suites.

**Capturing other hosts' traffic** (Diagnostics, Capture on an interface)
needs a packet capture library and the right to use it. Windows: install
[Npcap](https://npcap.com/) (Wireshark installs it). macOS: libpcap is built
in; install Wireshark's ChmodBPF or run as root. Linux: `libpcap` is usually
installed; give the binary the capability once with
`sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/sidetone-desktop` (or
the `sidetone` CLI), or run it with `sudo`. Everything else works without it.

**From source.** See [Get started](#get-started).

## Documentation

| Where | What it covers |
|---|---|
| [`docs/provisioning.md`](docs/provisioning.md) | provisioning XML, samples, and SIP resync |
| `sidetone --help`, `sidetone test-format` | every command and the test suite format |
| [`examples/`](examples/) | test suites, including one that fails on purpose |
| [`lab/`](lab/) | the Asterisk lab used by CI and the screenshots |
| [`crates/sidetone-core/src/rules.rs`](crates/sidetone-core/src/rules.rs) | every rule and its explanation |
| [`crates/sidetone-core/src/synth.rs`](crates/sidetone-core/src/synth.rs) | the sample scenarios |
| [`.github/workflows/`](.github/workflows/) | CI, releases and the GitHub Pages build |

---

## License and credits

Sidetone is licensed under the [MIT License](LICENSE).
Copyright &copy; 2026 Ighor Toth.

Written by Ighor Toth with Claude Code, Anthropic's AI coding assistant,
as co-author: commits it helped write carry a `Co-Authored-By` line.

Codecs: G.722 from libg722 (Steve Underwood, public domain, and CMU) through
the ezk-g722 translation (MIT); G.726 from soundkit-g726 (MIT); GSM 06.10 from
libgsm (Jutta Degener and Carsten Bormann, TU Berlin); Speex from libspeex
(Xiph.Org, BSD) and iLBC from WebRTC (BSD), both bundled in
`crates/sidetone-ua/native` with their licences; G.729 from the g729-sys crate,
which describes itself as MIT but is a port of bcg729 (GPL-3.0): builds that
must avoid GPL code can leave it out.

The interface uses IBM Plex Sans and IBM Plex Mono (SIL Open Font License),
loaded from Google Fonts. Every capture in the screenshots and samples was
made for Sidetone.

<sub>Sidetone is an independent open-source project, not affiliated with,
sponsored by or endorsed by any other software vendor. Product names such as
Wireshark and Asterisk belong to their owners and are used only to describe
compatibility. The software is provided "as is", without warranty of any
kind, as the license states.</sub>
