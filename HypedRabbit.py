#!/usr/bin/env python3

import asyncio
import argparse
import re
import json
import binascii
import base64
from datetime import datetime

import aiohttp
from playwright.async_api import async_playwright
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import MD5


KEYSERVER_URL = "http://127.0.0.1:5000/keys"
NEEDLE = ""
HOOK_PREFIX = "[KEYHOOK] PLAINTEXT:"
HEX_MIN_LEN = 32
HEX_RE = re.compile(r'[0-9A-Fa-f]{%d,}' % (HEX_MIN_LEN))


def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int):
    dt = b''
    prev = b''
    while len(dt) < (key_len + iv_len):
        m = MD5.new()
        m.update(prev + password + salt)
        prev = m.digest()
        dt += prev
    return dt[:key_len], dt[key_len:key_len+iv_len]

def openssl_decrypt_b64(b64text: str, passphrase: str):
    data = base64.b64decode(b64text)
    if not data.startswith(b"Salted__"):
        raise ValueError("Not OpenSSL salted format")
    salt = data[8:16]
    ct = data[16:]
    key, iv = evp_bytes_to_key(passphrase.encode('utf-8'), salt, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, AES.block_size)
    except Exception:
        pass
    return pt

def outer_decrypt_hex(cipher_hex: str, secret_hex: str, iv_hex: str):
    h = cipher_hex.strip().replace("\n","").replace(" ","")
    if len(h) % 2 != 0:
        h = h[:-1]
    ct = binascii.unhexlify(h)
    key = binascii.unhexlify(secret_hex)
    iv = binascii.unhexlify(iv_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, AES.block_size)
    except Exception:
        pass
    return pt

# === JS hook injected into page ===
HOOK_JS = r'''
(function() {
  if (!window.crypto || !window.crypto.subtle) {
    console.log("crypto.subtle not available");
    return;
  }
  const origEncrypt = window.crypto.subtle.encrypt;
  window.crypto.subtle.encrypt = async function(alg, key, data) {
    try {
      let arr = new Uint8Array(data instanceof ArrayBuffer ? data : (data.buffer || data));
      let decoded;
      try { decoded = new TextDecoder().decode(arr); }
      catch (e) { decoded = Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join(''); }
      console.log("[KEYHOOK] PLAINTEXT:" + decoded);
    } catch (e) { console.error("hook error", e); }
    return origEncrypt.apply(this, arguments);
  };
  console.log("Hook installed: window.crypto.subtle.encrypt");
})();
'''


def extract_encrypted_hex_from_post(post_data: str):
    if not post_data:
        return None
    s = post_data.strip()
    if re.fullmatch(r'[0-9A-Fa-f]+', s):
        return s
    m = HEX_RE.search(s)
    if m:
        return m.group(0)
    return None


async def post_keys_to_keyserver(session: aiohttp.ClientSession, iv_hex: str, secret_hex: str, page):
    """
    Gather correlation info (page URL, cookies, optionally localStorage keys)
    and POST to local key server. Non-blocking and robust.
    """
    try:
        # page.url and cookies
        page_url = page.url
        cookies = []
        try:
            cookies = await page.context.cookies()
        except Exception:
            # fallback: read document.cookie
            try:
                doc_cookie = await page.evaluate("() => document.cookie")
                cookies = [{"name": "document_cookie", "value": doc_cookie}] if doc_cookie else []
            except Exception:
                cookies = []

        cookie_str = ";".join([f"{c.get('name')}={c.get('value')}" for c in cookies])

        # try to fetch some localStorage keys that might correlate (clientid)
        local_clientid = None
        try:
            # common keys we might look for
            local_clientid = await page.evaluate("""
                () => {
                    try {
                        return localStorage.getItem('Clientid') || localStorage.getItem('clientid') || localStorage.getItem('clientId') || null;
                    } catch(e) { return null; }
                }
            """)
        except Exception:
            local_clientid = None

        payload = {
            "page_url": page_url,
            "cookie": cookie_str,
            "local_clientid": local_clientid,
            "iv": iv_hex,
            "secret": secret_hex,
            "ts": datetime.utcnow().isoformat()
        }
        
        try:
            async with session.post(KEYSERVER_URL, json=payload, timeout=3) as resp:
                # optionally check 200/201
                if resp.status in (200,201):
                    print("[*] Posted keys to keyserver")
                else:
                    txt = await resp.text()
                    print(f"[!] Keyserver returned status {resp.status}: {txt[:200]}")
        except Exception as e:
            print("[!] Failed to post keys to keyserver:", e)
    except Exception as e:
        print("[!] post_keys_to_keyserver error:", e)


async def run(target_url, click_selector=None, timeout=60):
    captured_keys = None  # (iv_hex, secret_hex)
    captured_requests = []

    async with aiohttp.ClientSession() as http_session:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=False)
            context = await browser.new_context()
            page = await context.new_page()

            async def handle_console(msg):
                nonlocal captured_keys
                try:
                    text_content = await msg.text()
                except TypeError:
                    text_content = msg.text if isinstance(msg.text, str) else None
                if not text_content:
                    return
                if HOOK_PREFIX in text_content:
                    payload = text_content.split(HOOK_PREFIX, 1)[1].strip()
                    print("[*] Console captured payload:", payload)
                    # parse CSV "IV,SECRET" or fallback to two hex tokens
                    iv_hex = None; secret_hex = None
                    if "," in payload:
                        a,b = [p.strip() for p in payload.split(",",1)]
                        # heuristics: shorter => iv
                        if len(a) <= len(b):
                            iv_hex, secret_hex = a, b
                        else:
                            iv_hex, secret_hex = b, a
                    else:
                        finds = re.findall(r'[0-9A-Fa-f]{16,}', payload)
                        if len(finds) >= 2:
                            iv_hex, secret_hex = finds[0], finds[1]
                    if iv_hex and secret_hex:
                        captured_keys = (iv_hex, secret_hex)
                        print(f"[*] Parsed keys -> IV: {iv_hex} SECRET(prefix): {secret_hex[:32]}...")
                        # asynchronously post keys to keyserver (do not await blocking)
                        # create a background task
                        asyncio.create_task(post_keys_to_keyserver(http_session, iv_hex, secret_hex, page))

            # request handler: capture POST hex body
            async def on_request(req):
                try:
                    if req.method.upper() != "POST":
                        return
                    # Playwright differences: try property then coro
                    post = None
                    try:
                        post = req.post_data
                    except Exception:
                        post = None
                    if not post:
                        try:
                            post = await req.post_data()
                        except Exception:
                            post = None
                    if not post:
                        return
                    hex_payload = extract_encrypted_hex_from_post(post)
                    if hex_payload:
                        print(f"[*] Detected POST -> {req.url} (hex len={len(hex_payload)})")
                        info = {"url": req.url, "headers": dict(req.headers), "hex": hex_payload, "ts": datetime.utcnow().isoformat()}
                        captured_requests.append(info)
                        # try local decrypt if keys already captured
                        if captured_keys:
                            iv_hex, secret_hex = captured_keys
                            try:
                                outer_plain = outer_decrypt_hex(hex_payload, secret_hex, iv_hex)
                                preview = outer_plain[:2048]
                                try:
                                    preview_text = preview.decode('utf-8', errors='replace')
                                except Exception:
                                    preview_text = repr(preview)
                                print("[+] Local outer decrypt preview:\n", preview_text[:1000])
                            except Exception as e:
                                print("[-] Local decrypt failed:", e)
                except Exception as e:
                    print("on_request error:", e)

            # wire events
            page.on("console", handle_console)
            page.on("request", lambda req: asyncio.create_task(on_request(req)))

            # inject hook before scripts run
            await context.add_init_script(HOOK_JS)

            print("[*] Opening target:", target_url)
            await page.goto(target_url)

            if click_selector:
                try:
                    await page.wait_for_selector(click_selector, timeout=10000)
                    print("[*] Auto-clicking selector:", click_selector)
                    await page.click(click_selector)
                except Exception as e:
                    print("[!] Auto-click failed:", e)
                    print("Please trigger the action manually in the opened browser.")

            print(f"[*] Running for up to {timeout}s. Interact with the UI to trigger key generation and POSTs.")
            end_time = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < end_time:
                # if keys captured and there are pending captured_requests, attempt local decrypt and also ensure keys were posted
                if captured_keys and captured_requests:
                    # try decrypt pending captures (non-blocking)
                    iv_hex, secret_hex = captured_keys
                    for req in captured_requests:
                        try:
                            outer_plain = outer_decrypt_hex(req["hex"], secret_hex, iv_hex)
                            preview_text = outer_plain[:2048].decode('utf-8', errors='replace')
                            print("\n" + "="*60)
                            print("[*] Decrypted request for:", req["url"])
                            print(preview_text[:1500])
                            # also print any inner OpenSSL fields if present
                            inner = re.findall(r'U2FsdGVk[0-9A-Za-z+/=]+', preview_text)
                            if inner:
                                for i,f in enumerate(inner,1):
                                    try:
                                        pt = openssl_decrypt_b64(f, NEEDLE)
                                        print(f"[+] Inner field #{i} decrypted: {pt.decode('utf-8', errors='replace')}")
                                    except Exception as e:
                                        print(f"[-] Inner field #{i} failed:", e)
                            print("="*60 + "\n")
                        except Exception as e:
                            print("[-] Decrypt pending req failed:", e)
                    captured_requests.clear()
                await asyncio.sleep(1)

            print("[*] Done waiting, closing browser.")
            await browser.close()

# === CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto-capture keys and post them to local Key Server (CTF use only).")
    parser.add_argument("url", help="Target URL to open")
    parser.add_argument("--click", help="Optional CSS selector to auto-click", default=None)
    parser.add_argument("--timeout", help="Seconds to run (default 60)", type=int, default=60)
    args = parser.parse_args()
    asyncio.run(run(args.url, args.click, args.timeout))
