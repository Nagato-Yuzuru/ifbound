"""Make urlhost.tsv: how Chromium reads host file fields.

Chromium reads the address field of a host line with the IPv4 and IPv6
parsers of its URL library, and a name field with the URL host
canonicalizer (net/dns/dns_hosts.cc). A URL in Chrome uses the same code.
This script runs the URL parser of a local Chrome on a fixed set of
fields and writes one line per field with three JSON values separated by
tabs:

  1. the field;
  2. the address that Chromium reads from the field, or null;
  3. the host that Chromium makes from the field as a URL host, or null.

The first line is "#chrome" and the Chrome version.

The field set leaves out the bytes that end a host inside a URL but not
inside a host file field ("/", "\\", "?", "#", "@", "[", "]"). The test
reads the host column only for a field without ":", and the address
column only for a field without "%".

Run it on macOS with Chrome installed:

  python3 -I urlhost.py > urlhost.tsv

Set CHROME to use another Chrome binary.
"""

import html
import json
import os
import random
import subprocess
import sys
import tempfile

CHROME = os.environ.get(
    "CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)
URL_BREAKERS = set("\t\n\r /\\?#@[]")


def address_fields(numerichost):
    """Fields from the macOS address corpus, plus URL-form spellings.

    The fields that macOS accepts are all used, the others in part.
    """
    out = set()
    rng = random.Random(1)
    with open(numerichost, encoding="latin-1") as f:
        for line in f:
            field, gai, pton = line.rstrip("\n").split("\t")
            if "%" not in field and (gai != "ERR" or pton != "ERR" or rng.random() < 0.25):
                out.add(field)
    parts = ["0", "00", "08", "010", "0377", "0400", "1", "255", "256", "4294967295",
             "4294967296", "0x", "0X", "0x0", "0xff", "0x100", "0xffffffff", "0x100000000",
             "0000000000000000001", "0x0000000000000000001", "1e1", ""]
    for n in range(1, 6):
        for _ in range(150):
            out.add(".".join(rng.choice(parts) for _ in range(n)) + rng.choice(["", "", "."]))
    for v6 in ["::ffff:", "::", "1:2:3:4:5:6:", "64:ff9b::"]:
        for v4 in ["010.0.0.1", "0x1.2.3.4", "1.2.3.4.", "1.2.3", "1.2.3.0377", "0177.0.0.1",
                   "1.2.3.4", "4294967295", "1.2.65535", "08.0.0.1"]:
            out.add(v6 + v4)
    return out


def name_fields():
    """Names in many spellings: ASCII, escapes, IDN, and address-like."""
    base = [
        "protected.example", "Protected.Example.", "_svc.example", "-a.example",
        "a-.example", "a_b.example", "xn--bcher-kva.example", "XN--BCHER-KVA.example",
        "xn--zz.example", "a..b", ".a", "a.", ".", "a.123", "a.0x10", "1.2.3.4",
        "1.2.3.4a", "0x7f.1", "127.1", "1.2.3.999", "999.example", "a.1.", "1a.2",
        "a*b.example", "a!b.example", "a$b", "a~b", "a`b", "a{b}", "a+b", "a=b",
        "a;b", "a'b", "a(b)", 'a"b', "a,b", "a|b", "a<b", "a>b", "a^b", "a%b",
        "\x01a", "a\x7f", "a\x00b", "a\x0bb", "a\x0cb", "a:b",
        "a" * 63 + ".example", "a" * 64 + ".example",
        ".".join(["a" * 63] * 3) + "." + "b" * 61, ".".join(["a" * 63] * 3) + "." + "b" * 61 + ".",
        ".".join(["a" * 63] * 3) + "." + "b" * 62, ".".join(["a" * 63] * 3) + "." + "b" * 62 + ".",
        "%70rotected.example", "%2570rotected.example", "%7", "%zz.example", "%41.example",
        "%c3%bc.example", "%C3%BCcher.example", "b%C3%BCcher.example", "%e2%80%8d.example",
        "%00.example", "%2e.example", "a%2eb", "%25.example", "%20.example", "%2a.example",
        "%ff.example", "%c3.example", "%5f.example", "%2d.example",
        "bücher.example", "BÜCHER.example", "ｅｘａｍｐｌｅ.com", "a．b", "a。b",
        "straße.example", "ß.example", "ς.example", "Σ.example", "İ.example", "ﬁ.example",
        "a­b.example", "a‍b.example", "a‌b.example", "الع.example",
        "אב.example", "א1.example", "1א.example", "日本.example",
        "\U0001f600.example", "�.example", "⒈.example", "a․b",
        "xn--bücher.example", "ü%70.example", "bü%2570.example", "bü%zz.example",
        "BÜ*X.example", "́a.example", "á.example", "가.example",
        "Ⅷ.example", "㍿.example", "Ｐｒｏｔｅｃｔｅｄ.example", "ｐ%72otected.example",
        "à.example", "à.example", "٠١.example", "۰.example",
        "０.example", "１２３.４", "０x7f.1", "a　b",
    ]
    pieces = ["a", "B", "-", "_", ".", "0", "9", "x", "%41", "%2e", "%c3%bc", "ü", "ß",
              "‍", "­", "．", "*", "!", "xn--", "א", "́", "１"]
    rng = random.Random(2)
    out = set(base)
    for _ in range(1500):
        out.add("".join(rng.choice(pieces) for _ in range(rng.randint(1, 8))) + rng.choice(["", ".example"]))
    return out


PAGE = """<!doctype html><meta charset="utf-8"><body><script>
const fields = %s;
const out = [];
for (const s of fields) {
  let host = null, addr = null;
  try { host = new URL("http://" + s + "/").hostname; } catch (e) {}
  if (s.includes(":")) {
    try { addr = new URL("http://[" + s + "]/").hostname.slice(1, -1); } catch (e) {}
  } else if (host !== null && /^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$/.test(host)) {
    addr = host;
  }
  out.push([s, addr, host]);
}
document.body.textContent = JSON.stringify(out);
</script>"""


def run_chrome(fields):
    with tempfile.TemporaryDirectory() as tmp:
        page = os.path.join(tmp, "page.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write(PAGE % json.dumps(fields))
        cmd = [CHROME, "--headless=new", "--disable-gpu", "--no-first-run",
               "--user-data-dir=" + os.path.join(tmp, "profile"), "--dump-dom", "file://" + page]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        dom = b""
        try:
            dom, _ = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()  # Chrome can stay alive after it prints the DOM
            dom, _ = proc.communicate()
    text = dom.decode("utf-8")
    body = text[text.index("<body>") + len("<body>"):text.index("</body>")]
    return json.loads(html.unescape(body))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    fields = address_fields(os.path.join(here, "numerichost.tsv")) | name_fields()
    fields = sorted(f for f in fields if not (set(f) & URL_BREAKERS))
    version = subprocess.run([CHROME, "--version"], capture_output=True, text=True).stdout.strip()
    print("#chrome\t" + json.dumps(version))
    for field, addr, host in run_chrome(fields):
        print("\t".join(json.dumps(v, ensure_ascii=False) for v in (field, addr, host)))


if __name__ == "__main__":
    sys.exit(main())
