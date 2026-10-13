"""Make readers.txt: how the two macOS readers read generated host files.

The script generates host files with a fixed seed, runs readers.c on
them, and writes one block per file:

  F <file content as a Go string literal>
  <the records of readers.c for the file>

Two kinds of file are generated. A structured file has lines of an
address and names, with the spellings that the readers treat in
different ways. A noise file is random text from a small alphabet, with
lines that cross the chunk sizes of the readers.

Run it on macOS:

  python3 -I readers.py > readers.txt
"""

import os
import random
import subprocess
import sys
import tempfile

ADDRS = ["1.2.3.4", "10.0.0.1", "010.000.000.001", "192.168.001.010", "127.1", "10.0.1",
         "0x0a000001", "167772161", "0177.0.0.1", "::1", "fd00::10", "00001::", "::ffff:1.2.3.4",
         "::ffff:010.0.0.1", "::1.2.3.4", "fe80::1%en0", "10.0.0.1%en0", "10.0.0.1%lo0",
         "10.0.0.1%bogus9", "1.2.3.4.", "1.2.3.256", "bogus", "#1.2.3.4", "1.2.3.4#x", "4294967297",
         "0x", "08"]
NAMES = ["protected.example", "a.example", "Protected.Example.", "p\\rotected.example",
         "protected.example\\", "x#y", "#c", "#", "a.example#b", "s\\1.example", "\\256.example",
         "\\065b.example", "a..b", ".", "a.example.", "b.example", "x" * 64 + ".example",
         "%70rotected.example", "bücher.example", "a\\.b.example", "protected.example.\\",
         "nas.lan", "\\", "a\\", "q\\0659.example"]
SEPS = [" ", "\t", ",", " , ", "\t\t", "  ", ", ", "\t,"]


def structured(rng):
    def name():
        if rng.random() < 0.9:
            return rng.choice(NAMES)
        return "".join(rng.choice("ab.\\#,% 09x") for _ in range(rng.randint(1, 8)))

    def line():
        if rng.random() < 0.05:
            return "#" + "x" * rng.choice([10, 1022, 1023, 1024, 4094, 4095, 4096]) + rng.choice(
                ["", " 1.2.3.4 protected.example", "1.2.3.4 protected.example"])
        s = rng.choice(["", "", "", " ", "\t", ",", "\r"]) + rng.choice(ADDRS)
        for _ in range(rng.choice([0, 1, 1, 2, 3, 4])):
            s += rng.choice(SEPS) + name()
        if rng.random() < 0.1:
            s += rng.choice(SEPS) + "#" + rng.choice(["", " ", "x"]) + rng.choice(
                ["comment", " protected.example", "protected.example"])
        if rng.random() < 0.05:
            pad = rng.choice([900, 1000, 1010, 1020, 4000, 4080, 4090])
            s += " " + "y" * rng.randint(1, 30) + "." + "z" * rng.randint(1, 30)
            while len(s) < pad:
                s += " p%d%s.example" % (rng.randint(0, 99), "q" * 50)
            s += rng.choice(SEPS) + rng.choice(["protected.example", "1.2.3.4 protected.example"])
        if rng.random() < 0.02:
            s = s[:rng.randint(0, len(s))] + "\x00" + s[rng.randint(0, len(s)):]
        if rng.random() < 0.05:
            s += rng.choice(SEPS)
        return s

    lines = [line() for _ in range(rng.randint(1, 6))]
    end = rng.choice(["\n", "\n", "\n", "\r\n"])
    return (end.join(lines) + rng.choice([end, end, ""])).encode("utf-8")


NOISE = (list("0123456789.:,% \t#\\xabp\r") + ["\x00"] +
         ["1.2.3.4 ", " protected.example", "::1 ", "010.0.0.1 ", "%en0 ", "\n", "#", "fe80::1",
          "1.2.3.4,", "\r\n"])
NOISE_WEIGHTS = [3] * 10 + [6, 4, 3, 2, 6, 6, 2, 2, 2, 2, 1, 1, 2] + [1] + [6, 6, 3, 3, 2, 3, 4, 2, 2, 2]


def noise(rng):
    target = rng.choice([20, 50, 200, 1030, 4100])
    out, n = [], 0
    while n < target:
        t = rng.choices(NOISE, weights=NOISE_WEIGHTS)[0]
        if rng.random() < 0.01:
            t = "y" * rng.choice([500, 1000, 1015, 1020, 1023, 4090, 4095])
        out.append(t)
        n += len(t)
    return "".join(out).encode("latin-1")


def go_quote(b):
    """Quote bytes as a Go interpreted string literal."""
    special = {0x22: '\\"', 0x5c: "\\\\", 0x0a: "\\n", 0x0d: "\\r", 0x09: "\\t"}
    out = []
    for c in b:
        if c in special:
            out.append(special[c])
        elif 0x20 <= c < 0x7f:
            out.append(chr(c))
        else:
            out.append("\\x%02x" % c)
    return '"' + "".join(out) + '"'


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    rng = random.Random(20261013)
    files = [structured(rng) for _ in range(200)] + [noise(rng) for _ in range(30)]
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "readers")
        subprocess.run(["cc", "-O2", "-o", binary, os.path.join(here, "readers.c")], check=True)
        paths = []
        for i, content in enumerate(files):
            path = os.path.join(tmp, "h%05d" % i)
            with open(path, "wb") as f:
                f.write(content)
            paths.append(path)
        out = subprocess.run([binary] + paths, check=True, capture_output=True).stdout.decode("ascii")
    by_path = dict(zip(paths, files))
    for line in out.splitlines():
        if line.startswith("F "):
            print("F " + go_quote(by_path[line[2:]]))
        else:
            print(line)


if __name__ == "__main__":
    sys.exit(main())
