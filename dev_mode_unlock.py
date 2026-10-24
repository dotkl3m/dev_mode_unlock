import sys, os, re, zipfile, struct, base64, hashlib

AES_MARKER = b"Lcom/android/tv/settings/about/AESUtils;"
PIN_MARKER = b"Lcom/android/tv/settings/dialog/PinDialogFragment;"
PIN_OK     = "PIN_DIALOG_RESULT_SUCCESS"

_SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def _key_expansion(key):
    Nk, Nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        t = list(w[i - 1])
        if i % Nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // Nk - 1]
        elif i % Nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - Nk][j] ^ t[j] for j in range(4)])
    return w

def _encrypt_block(block, w):
    s = [[block[c * 4 + r] for c in range(4)] for r in range(4)]

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]

    add_round_key(0)
    for rnd in range(1, 14):
        for r in range(4):
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
            s[3][c] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
        add_round_key(rnd)
    for r in range(4):
        for c in range(4):
            s[r][c] = _SBOX[s[r][c]]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    add_round_key(14)
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = s[r][c]
    return bytes(out)

def _aes256_ecb(data, key):
    w = _key_expansion(key)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += _encrypt_block(data[i:i + 16], w)
    return bytes(out)

def _pkcs7(d, bs=16):
    p = bs - (len(d) % bs)
    return d + bytes([p]) * p

def compute_pin(sn, secret):
    plain = sn + secret
    key = hashlib.pbkdf2_hmac('sha1', plain.encode(), b'sdmc', 10000, dklen=16).hex().encode()
    ct = _aes256_ecb(_pkcs7(plain.encode()), key)
    b64 = base64.b64encode(ct).decode()
    return (b64[:3] + b64[-3:]).lower()


def _uleb(d, o):
    r = s = 0
    while True:
        b = d[o]; o += 1; r |= (b & 0x7f) << s
        if not b & 0x80:
            break
        s += 7
    return r, o

def dex_strings(d, cb=None):
    if len(d) < 0x70:
        return []
    n = struct.unpack_from('<I', d, 0x38)[0]
    off = struct.unpack_from('<I', d, 0x3C)[0]
    out = []
    step = max(1, n // 50)
    for i in range(n):
        sdo = struct.unpack_from('<I', d, off + i * 4)[0]
        _, p = _uleb(d, sdo)
        e = d.index(0, p)
        out.append(d[p:e].decode('utf-8', 'replace'))
        if cb and i % step == 0:
            cb(i / n)
    return out

def const_string_offsets(d, idx):
    res = []
    if idx <= 0xffff:
        lo, hi = idx & 0xff, (idx >> 8) & 0xff
        o = 0
        while True:
            j = d.find(b'\x1a', o)
            if j < 0 or j + 3 >= len(d):
                break
            if d[j + 2] == lo and d[j + 3] == hi:
                res.append(j)
            o = j + 1
    else:
        b = struct.pack('<I', idx)
        o = 0
        while True:
            j = d.find(b'\x1b', o)
            if j < 0 or j + 5 >= len(d):
                break
            if d[j + 2:j + 6] == b:
                res.append(j)
            o = j + 1
    return res

def _pick_pin(d, strs, cand):
    if len(cand) == 1:
        return strs[cand[0]]
    try:
        mk = strs.index(PIN_OK)
    except ValueError:
        mk = -1
    if mk >= 0:
        mko = const_string_offsets(d, mk)
        if mko:
            best, bd = None, 1 << 60
            for ci in cand:
                for o in const_string_offsets(d, ci):
                    for m in mko:
                        if abs(o - m) < bd:
                            bd, best = abs(o - m), ci
            if best is not None and bd <= 4096:
                return strs[best]
    def tech(s):
        v = int(s)
        return v <= 0 or (v & (v - 1)) == 0 or v % 1024 == 0 or v % 100000 == 0
    filt = [ci for ci in cand if not tech(strs[ci])]
    return strs[filt[0]] if len(filt) == 1 else None

def analyze(apk_path, progress=None):
    aes_consts, pins = set(), set()
    saw_aes = saw_pin = False
    hex32 = re.compile(r'^[0-9a-fA-F]{32}$')
    six = re.compile(r'^\d{6}$')
    with zipfile.ZipFile(apk_path) as z:
        names = [n for n in z.namelist() if re.match(r'classes\d*\.dex$', n)]
        K = len(names) or 1
        for k, name in enumerate(names):
            base, span = k / K, 1 / K
            try:
                d = z.read(name)
                has_aes = AES_MARKER in d
                has_pin = PIN_MARKER in d
                saw_aes = saw_aes or has_aes
                saw_pin = saw_pin or has_pin
                if has_aes or has_pin:
                    strs = dex_strings(
                        d, cb=lambda f: progress and progress(2 + 96 * (base + f * span)))
                    if has_aes:
                        for s in strs:
                            if hex32.match(s):
                                aes_consts.add(s.lower())
                    if has_pin:
                        cand = [i for i, s in enumerate(strs) if six.match(s)]
                        if cand:
                            pin = _pick_pin(d, strs, cand)
                            if pin:
                                pins.add(pin)
            except Exception:
                pass
            if progress:
                progress(2 + 96 * (base + span))
    if progress:
        progress(100)
    return {
        'aes_const': aes_consts.pop() if len(aes_consts) == 1 else None,
        'fixed_pin': pins.pop() if len(pins) == 1 else None,
        'saw_aes': saw_aes,
        'saw_pin': saw_pin,
    }


def _show(code):
    title = "===== CODE DU MODE DEVELOPPEUR DE VOTRE DECODEUR ====="
    print(title)
    print(code.center(len(title)))
    print("=" * len(title))

def _clean_path(p):
    return p.strip().strip('"').strip("'").strip()

def _ask_apk():
    while True:
        try:
            p = input("Chemin absolu de l'APK parametres de votre decodeur : ")
        except (EOFError, KeyboardInterrupt):
            return None
        p = _clean_path(p)
        if not p:
            return None
        if os.path.isfile(p):
            return p
        print("Fichier introuvable. Reessaie, ou Entree pour quitter.")

def _pause():
    try:
        input("\nAppuie sur Entree pour quitter...")
    except (EOFError, KeyboardInterrupt):
        pass

def main():
    apk = _clean_path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not apk or not os.path.isfile(apk):
        print("Information : avant d'utiliser ce script vous devez avoir l'APK des parametres "
              "de votre decodeur, vous pouvez la recuperer via un explorateur de fichier.")
        apk = _ask_apk()
    if not apk:
        print("Aucune APK.")
        _pause(); return

    try:
        r = analyze(apk)
    except Exception:
        print("APK illisible.")
        _pause(); return

    if r['aes_const']:
        try:
            serial = input("Numero de serie du decodeur : ").strip()
        except (EOFError, KeyboardInterrupt):
            serial = ""
        code = compute_pin(serial, r['aes_const']) if serial else "(numero de serie manquant)"
    elif r['fixed_pin']:
        code = r['fixed_pin']
    elif r['saw_aes']:
        code = "(constante introuvable)"
    elif r['saw_pin']:
        code = "(code introuvable)"
    else:
        code = "(aucun code)"

    _show(code)
    _pause()


if __name__ == '__main__':
    main()