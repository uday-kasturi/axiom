#!/usr/bin/env python3
"""
Capture Muse Spark auth and message-sending protocol from meta.ai.

CDP intercepts both HTTP requests AND WebSocket frames — the actual chat
message is likely sent via a GraphQL subscription over WebSocket.

Usage:
  1. Launch Chrome with debugging:
     pkill -a "Google Chrome"; sleep 2
     /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
       --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-axiom \
       https://www.meta.ai
  2. Log in to meta.ai in that Chrome window
  3. Run this script (you have 90 seconds)
  4. Send a chat message in the browser
  5. The script captures everything and saves to muse_auth.json
"""
import asyncio, json, httpx, websockets
from collections import defaultdict


async def main():
    tabs = httpx.get("http://127.0.0.1:9222/json").json()
    tab  = next((t for t in tabs if "meta.ai" in t.get("url", "")), None)
    if not tab:
        print("No meta.ai tab found. Is Chrome running with --remote-debugging-port=9222?")
        return

    print(f"Attached to: {tab['url'][:80]}\n")
    print("Send a chat message in meta.ai now. Capturing for 90 seconds...\n")

    captured_cookie = ""
    graphql_http:  list[dict] = []   # HTTP POST /api/graphql calls
    ws_frames:     list[dict] = []   # WebSocket frames on meta.ai connections
    ws_url_map:    dict[str, str] = {}  # requestId → url

    async with websockets.connect(tab["webSocketDebuggerUrl"], max_size=50_000_000) as ws:
        # Enable Network events (HTTP + WebSocket)
        await ws.send(json.dumps({"id": 1, "method": "Network.enable"}))
        await ws.recv()

        deadline = asyncio.get_event_loop().time() + 90

        while asyncio.get_event_loop().time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
            except asyncio.TimeoutError:
                continue

            msg    = json.loads(raw)
            method = msg.get("method", "")
            params = msg.get("params", {})

            # ── HTTP cookies ──────────────────────────────────────────────
            if method == "Network.requestWillBeSentExtraInfo":
                h = params.get("headers", {})
                c = h.get("cookie", "") or h.get("Cookie", "")
                if c and "ecto_1_sess" in c and len(c) > len(captured_cookie):
                    captured_cookie = c

            # ── HTTP GraphQL POST ─────────────────────────────────────────
            if method == "Network.requestWillBeSent":
                req = params.get("request", {})
                url = req.get("url", "")
                if "meta.ai/api/graphql" in url:
                    body = req.get("postData", "")
                    graphql_http.append({"url": url, "body": body})
                    try:
                        parsed  = json.loads(body)
                        doc_id  = parsed.get("doc_id", "?")[:16]
                        vk      = list(parsed.get("variables", {}).keys())
                        print(f"  HTTP graphql ({len(body)}b) doc_id={doc_id} vars={vk}")
                    except Exception:
                        print(f"  HTTP graphql ({len(body)}b) unparseable")

            # ── WebSocket lifecycle ───────────────────────────────────────
            if method == "Network.webSocketCreated":
                rid = params.get("requestId", "")
                url = params.get("url", "")
                if "meta.ai" in url or "facebook" in url:
                    ws_url_map[rid] = url
                    print(f"  WS opened: {url[:80]}")

            # ── WebSocket frames (sent from browser to server) ────────────
            if method == "Network.webSocketFrameSent":
                rid  = params.get("requestId", "")
                url  = ws_url_map.get(rid, "")
                data = params.get("response", {}).get("payloadData", "")
                if data and len(data) > 20:
                    ws_frames.append({"direction": "sent", "url": url, "data": data})
                    snippet = data[:200].replace("\n", " ")
                    print(f"  WS SENT ({len(data)}b): {snippet}")

            # ── WebSocket frames (received from server) ───────────────────
            if method == "Network.webSocketFrameReceived":
                rid  = params.get("requestId", "")
                url  = ws_url_map.get(rid, "")
                data = params.get("response", {}).get("payloadData", "")
                if data and len(data) > 20:
                    ws_frames.append({"direction": "recv", "url": url, "data": data})
                    # only print large frames (they have content)
                    if len(data) > 100:
                        snippet = data[:200].replace("\n", " ")
                        print(f"  WS RECV ({len(data)}b): {snippet}")

    # sort HTTP calls largest-first to find the mutation
    graphql_http.sort(key=lambda x: len(x.get("body", "")), reverse=True)

    # find any WS sent frame that looks like a message (contains "message" or is large JSON)
    ws_msg_candidates = []
    for frame in ws_frames:
        if frame["direction"] != "sent":
            continue
        try:
            parsed = json.loads(frame["data"])
            # look for 'message', 'text', 'content' in nested payload
            dumped = json.dumps(parsed)
            if any(k in dumped.lower() for k in ("message", '"text"', '"content"', '"prompt"')):
                ws_msg_candidates.append({"raw": frame["data"], "parsed": parsed})
        except Exception:
            if len(frame["data"]) > 200:
                ws_msg_candidates.append({"raw": frame["data"]})

    result = {
        "cookie":              captured_cookie,
        "graphql_http":        graphql_http,
        "ws_sent_frames":      [f for f in ws_frames if f["direction"] == "sent"][:20],
        "ws_msg_candidates":   ws_msg_candidates,
        # legacy keys for backward compatibility
        "graphql_calls":       graphql_http,
        "send_mutation":       graphql_http[0] if graphql_http else None,
    }
    with open("muse_auth.json", "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*60}")
    print(f"HTTP graphql calls: {len(graphql_http)}")
    print(f"WebSocket frames:   {len(ws_frames)}  ({len(ws_msg_candidates)} message candidates)")
    print(f"Cookie:             {'✓' if captured_cookie else '✗'}")
    print(f"Saved → muse_auth.json")

    if ws_msg_candidates:
        print(f"\nBest WS candidate:")
        print(ws_msg_candidates[0]["raw"][:600])

asyncio.run(main())
