# Presenting ThreatLens to Judges

A field guide for a 7-minute live demo: setup, a timed script with talking points, honest
answers to the questions judges ask, and what to do if something breaks on stage.

**The one-sentence story:** *ThreatLens watches a company's logs in real time, links every step of
an attack into one story, explains its reasoning, and responds automatically — and I'll prove it
by attacking a real server in front of you.*

---

## 1. The day before (30 minutes)

1. **Build everything once** (first build downloads images and takes ~10 minutes):
   ```powershell
   docker compose --profile lab up -d --build
   ```
2. **Add your free API keys** to `.env` (see `.env.example` for where to get each):
   - `GROQ_API_KEY` — **strongly recommended.** Without it the Copilot still answers, but with a
     structured briefing instead of a conversation.
   - `VT_API_KEY` — optional, adds VirusTotal reputation in Threat Studio.

   Then apply them: `docker compose up -d`.
3. **Create your admin account:** open http://localhost:8080 → *Create account*. The first account
   is the administrator.
4. **The judges' read-only account** already exists: username `judge`, password = the
   `DEMO_VIEWER_PASSWORD` value in your `.env`. Judges can click around on their own devices and
   watch things update live, but cannot change anything.
5. **Rehearse the script below twice**, out loud, with a timer.

> Port note: on your machine the API is on **8001** and PostgreSQL on **5433** (`BACKEND_PORT` /
> `POSTGRES_PORT` in `.env`) because your TripMind project uses 8000 and 5432. The app itself is
> always http://localhost:8080.

## 2. Ten minutes before you present

1. `docker compose --profile lab up -d` and wait until `docker compose ps` shows **healthy**.
2. Sign in at http://localhost:8080.
3. **Live Demo → Reset demo data** (clean slate), then **Start traffic** at *normal*.
4. Open browser tabs in this order: **Landing (/)**, **Dashboard**, **Live Demo**, **Threat Map**,
   **Campaigns**, **Copilot**, **Executive View**.
5. Open a terminal next to the browser, already in the project folder, with this typed but not run:
   ```powershell
   docker compose --profile lab run --rm attacker all
   ```
6. Browser zoom ~110 % so judges can read it; close notifications; plug in power.

**Optional — give judges a link to open on their phones** (uses the `cloudflared` you already have
installed; no account needed, the link works only while the command runs):
```powershell
cloudflared tunnel --url http://localhost:8080
```
Share the `https://….trycloudflare.com` address with the `judge` login. Stop it (Ctrl+C) after the
presentation — while it runs, your instance is reachable from the internet.

## 3. The 7-minute script

| Time | Screen | Do | Say |
|---|---|---|---|
| 0:00 | **Landing page** | Scroll slowly through the hero. | "Security teams drown in thousands of disconnected alerts. IBM measured 277 days on average to identify and contain a breach. ThreatLens turns raw logs into a few explained cases and responds automatically." |
| 0:30 | **Dashboard** | Point at the green **LIVE** pill, the *Detection Engine* card (events/min, latency) and the *Live Event Stream*. | "This is live. A simulated company network is sending logons, web traffic and DNS — and the internet noise every company sees. Those attacker IPs come from real public blocklists. Every event goes through the real detection pipeline in milliseconds." |
| 1:15 | **Live Demo** | Set **2×**, click **Launch** on *Ransomware intrusion*. Narrate as steps tick and red alerts pop up. | "Now a ransomware gang. Port scan… RDP brute force… they're in — CRITICAL, automatic. PowerShell downloads a payload, they dump credentials from LSASS, jump to the domain controller, delete backups, encrypt files. Each stage was detected the moment it happened." |
| 2:45 | **Threat Map** | Hover one red point; point at arcs to your HQ. | "Every attacker, geolocated from its real IP. The ones marked are already blocked — by the platform, not by a person." |
| 3:15 | **Campaigns** → open the newest campaign | Show the lit kill-chain stages and the timeline. | "Instead of nine separate alerts, analysts get one campaign: the whole kill chain, in order, with every linked case." |
| 3:45 | **Terminal + Dashboard side by side** | Run the attacker command. | "Simulations are nice — this isn't one. That's a real Linux server and real hacking tools: nmap, sqlmap, hydra. A log shipper sends the server's genuine logs to ThreatLens… there's the scan… SQL injection… hydra cracked the password — CRITICAL, *successful login after brute force*… and SOAR has already blocked the attacker." |
| 5:15 | **Copilot** | Ask: *"What happened in the last hour? Which attackers got in?"* | "Analysts can just ask. The answer comes from the live database, not from the model's imagination." |
| 5:45 | **Any CRITICAL incident** → set Owner = you, Status = *Investigating*, then *Resolved* | Then open **Executive View**. | "Here's the analyst workflow — and leadership sees it immediately: time to triage, time to resolve, SLA compliance, how much noise was removed, how much was automated. Every number is computed from real case data." |
| 6:30 | **Executive View** / README | Close with credibility. | "28 detection rules mapped to MITRE ATT&CK, 78 automated tests, a CI pipeline, and validation on 261 real attack recordings from a public research dataset — the script is in the repo so anyone can reproduce it." |
| 7:00 | — | Stop. Invite questions. | "Thank you — happy to attack anything you'd like." |

**Golden rules on stage:** narrate what *just happened*, not what's about to happen; if a toast
appears, click it; never claim a feature that isn't on screen.

## 4. Questions judges ask — honest answers

**"Is any of this real, or is it all simulated?"**
Three layers: (1) the *attack lab* is completely real — real server, real tools, real logs;
(2) the *scenarios and background traffic* are generated log lines, but they go through exactly
the same pipeline, and attacker IPs are real addresses from public blocklists; (3) threat-intel
feeds (CISA KEV, abuse.ch, IPsum), MITRE ATT&CK data and geolocation are live external sources.

**"Where's the AI?"**
The Groq-hosted Llama model writes the incident analysis and powers the conversational Copilot,
grounded by retrieval over a threat knowledge base and the CISA KEV catalogue. Detection itself is
deliberately rule-based and transparent — security teams need to know *why* something fired. If the
AI is unavailable, a rule engine produces the same report sections, so the product never depends on it.

**"How good is the detection?"**
Measured, not claimed: against the public EVTX-ATTACK-SAMPLES dataset (261 recordings of real
Windows attacks), ThreatLens flags **93 recordings (36 %)**; strongest on privilege escalation
(48 %) and credential access (44 %). Commercial products use thousands of rules; ThreatLens uses 28
hand-written ones. The obvious next step is importing the open Sigma rule library.
Run it yourself: `python -m benchmarks.evtx_validation --download`.

**"Does it scale?"**
Measured on a laptop: about **90 events/second per worker** with a median of **9 ms** per event
on PostgreSQL (`benchmarks/throughput.py`) — roughly 8 million events a day on one worker. The API
is stateless behind nginx; scaling out means more workers and moving the scheduler to its own process.

**"How is this different from Splunk or Microsoft Sentinel?"**
It isn't a replacement — those are enterprise platforms. ThreatLens shows the full SOC loop
(ingest → detect → correlate → explain → respond → report) in one transparent system, with every
risk point explained and every automated action audited.

**"Is the platform itself secure?"**
Role-based access (admin / analyst / read-only), bcrypt password hashing, short-lived JWTs with
refresh, an immutable audit log, rate-limited login, single-use tickets for the live stream so
tokens never appear in URLs, SSRF protection on asset checks, security headers, and an API key for
machine log ingestion.

**"What did you build versus use?"**
Built: the parser, detection engine, campaign correlation, risk model, case management, SOAR,
simulator, attack lab, live streaming, every UI page. Used: FastAPI, PostgreSQL, React, public
threat-intel feeds, MITRE ATT&CK data, and (optionally) Groq for the language model.

## 5. If something goes wrong

| Symptom | Fix (≤ 30 seconds) |
|---|---|
| http://localhost:8080 shows a blank page or "empty response" | `docker compose up -d --force-recreate frontend`, then refresh |
| The pill says **OFFLINE** | Refresh the page; check `docker compose ps` shows backend *healthy* |
| Threat map is empty | It needs internet for geolocation and retries every 15 s; switch to the **7 days** window |
| *Launch* buttons are greyed out | A scenario is still running — click **Stop** in Scenario progress |
| Attacker says "password not found" | `docker compose --profile lab up -d victim`, wait 5 s, run it again |
| Copilot answers with a plain briefing | That's the fallback when `GROQ_API_KEY` is missing or the internet is down — say so, it's by design |
| No internet at the venue | Detection, scenarios, the lab, campaigns, SOAR and the Executive View all work offline. Feeds, map geolocation and the LLM need internet — mention it and move on |

## 6. Command cheat sheet

```powershell
docker compose --profile lab up -d --build            # start everything (first time / after changes)
docker compose ps                                     # health check
docker compose --profile lab run --rm attacker all    # real attack (~2 min), or: recon | web | bruteforce | post | exfil
docker compose logs -f backend                        # watch detections in the API log
docker compose --profile lab down                     # stop (keeps data)
docker compose --profile lab down -v                  # stop and wipe everything
```
