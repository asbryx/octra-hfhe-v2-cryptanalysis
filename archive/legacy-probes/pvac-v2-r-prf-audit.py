from pathlib import Path
from collections import defaultdict
from Crypto.Cipher import AES
import hashlib
import struct

ROOT = Path('bounty2_data')
MASK64 = (1 << 64) - 1
P = (1 << 127) - 1


def fnv1a(text):
    value = 0xcbf29ce484222325
    for byte in text.encode('ascii'):
        value = ((value ^ byte) * 0x100000001b3) % (1 << 64)
    return value


def field_mul(left, right):
    return left * right % P


def fp_words(raw, offset):
    lo, hi = struct.unpack_from('<QQ', raw, offset)
    return lo | (hi << 64), offset + 16


def read_pk():
    raw = (ROOT / 'pk.bin').read_bytes()
    offset = 8
    m, basis, lpn_t, lpn_n, tau_num, tau_den, _, _ = struct.unpack_from('<8I', raw, offset)
    offset += 32 + 8 + 4
    canon, = struct.unpack_from('<Q', raw, offset)
    offset += 8
    h_digest = raw[offset:offset + 32]
    offset += 32
    count, = struct.unpack_from('<Q', raw, offset)
    offset += 8
    for _ in range(count):
        bits, = struct.unpack_from('<I', raw, offset)
        offset += 4 + ((bits + 63) // 64) * 8
    count, = struct.unpack_from('<Q', raw, offset)
    offset += 8 + count * 4
    count, = struct.unpack_from('<Q', raw, offset)
    offset += 8 + count * 4
    _, offset = fp_words(raw, offset)
    count, = struct.unpack_from('<Q', raw, offset)
    offset += 8
    powers = []
    for _ in range(count):
        value, offset = fp_words(raw, offset)
        powers.append(value)
    assert offset == len(raw)
    return {'m': m, 'basis': basis, 't': lpn_t, 'n': lpn_n,
            'num': tau_num, 'den': tau_den, 'canon': canon,
            'h_digest': h_digest, 'powers': powers}


def read_sk():
    raw = (ROOT / 'sk.bin').read_bytes()
    assert struct.unpack_from('<II', raw) == (0x66666999, 1)
    prf_key = struct.unpack_from('<4Q', raw, 8)
    count, = struct.unpack_from('<Q', raw, 40)
    secret = list(struct.unpack_from('<%dQ' % count, raw, 48))
    assert 48 + 8 * count == len(raw)
    return prf_key, secret


def read_ct(name):
    raw = (ROOT / name).read_bytes()
    assert struct.unpack_from('<IIQ', raw) == (0x66699666, 1, 1)
    offset = 16
    layer_count, edge_count = struct.unpack_from('<II', raw, offset)
    offset += 8
    layers = []
    for _ in range(layer_count):
        assert raw[offset] == 0
        offset += 1
        layers.append(struct.unpack_from('<QQQ', raw, offset))
        offset += 24
    edges = []
    for _ in range(edge_count):
        layer, index = struct.unpack_from('<IH', raw, offset)
        offset += 6
        sign = raw[offset]
        offset += 2
        weight, offset = fp_words(raw, offset)
        bits, = struct.unpack_from('<I', raw, offset)
        offset += 4 + ((bits + 63) // 64) * 8
        edges.append((layer, index, sign, weight))
    assert offset == len(raw)
    return layers, edges


class AesCtr:
    def __init__(self, key, nonce):
        self.cipher = AES.new(key, AES.MODE_ECB)
        self.counter = nonce
        self.buffered = None

    def block(self):
        output = self.cipher.encrypt(struct.pack('<QQ', self.counter, 0))
        self.counter = (self.counter + 1) % (1 << 64)
        return struct.unpack('<QQ', output)

    def next_u64(self):
        if self.buffered is not None:
            output = self.buffered
            self.buffered = None
            return output
        first, second = self.block()
        self.buffered = second
        return first

    def fill_u64(self, count):
        output = []
        if self.buffered is not None and count:
            output.append(self.buffered)
            self.buffered = None
        while len(output) + 1 < count:
            output.extend(self.block())
        if len(output) < count:
            first, second = self.block()
            output.append(first)
            self.buffered = second
        return output

    def bounded(self, modulus):
        if modulus <= 1:
            return 0
        limit = MASK64 - (MASK64 % modulus)
        while True:
            candidate = self.next_u64()
            if candidate < limit:
                return candidate % modulus


def aes_material(pk, prf_key, seed, domain):
    ztag, nonce_lo, nonce_hi = seed
    digest = hashlib.sha256()
    for word in prf_key:
        digest.update(struct.pack('<Q', word))
    digest.update(struct.pack('<Q', pk['canon']))
    digest.update(pk['h_digest'])
    digest.update(struct.pack('<QQQ', ztag, nonce_lo, nonce_hi))
    domain_hash = fnv1a(domain)
    digest.update(struct.pack('<Q', domain_hash))
    return digest.digest(), domain_hash ^ nonce_lo


def prf_core(pk, secret_key, seed, domain):
    key, nonce = aes_material(pk, secret_key[0], seed, domain)
    stream = AesCtr(key, nonce)
    ybits = [0] * ((pk['t'] + 63) // 64)
    for row in range(pk['t']):
        row_words = stream.fill_u64((pk['n'] + 63) // 64)
        dot = 0
        for row_word, secret_word in zip(row_words, secret_key[1]):
            dot ^= row_word & secret_word
        bit = dot.bit_count() % 2
        error = int(stream.bounded(pk['den']) < pk['num'])
        ybits[row // 64] ^= (bit ^ error) << (row % 64)

    key, nonce = aes_material(pk, secret_key[0], seed, 'pvac.dom.toeplitz')
    stream = AesCtr(key, nonce ^ fnv1a(domain))
    top = stream.fill_u64((pk['t'] + 127 + 63) // 64)
    low_y = ybits[0] | ((ybits[1] % (1 << 63)) << 64)
    low_top = top[0] | ((top[1] % (1 << 63)) << 64)
    output = 0
    while low_y:
        bit = low_y & -low_y
        output ^= low_top << (bit.bit_length() - 1)
        low_y ^= bit
    output %= 1 << 127
    return 1 if output == 0 else output


def prf_r(pk, secret_key, seed, noise):
    domains = ('pvac.prf.noise.1', 'pvac.prf.noise.2', 'pvac.prf.noise.3') if noise else (
        'pvac.prf.r.1', 'pvac.prf.r.2', 'pvac.prf.r.3')
    output = 1
    for domain in domains:
        output = field_mul(output, prf_core(pk, secret_key, seed, domain))
    return output


def noise_delta(pk, secret_key, seed, group_id, kind):
    ztag, nonce_lo, nonce_hi = seed
    group = group_id + 1
    domain = kind + 1
    nonce_lo ^= (0x9e3779b97f4a7c15 * group) % (1 << 64)
    nonce_hi ^= (0x94d049bb133111eb * group) % (1 << 64)
    ztag ^= (0x517cc1b727220a95 * group) % (1 << 64)
    nonce_lo ^= domain
    nonce_hi ^= domain << 32
    ztag ^= domain << 48
    return prf_r(pk, secret_key, (ztag % (1 << 64), nonce_lo % (1 << 64), nonce_hi % (1 << 64)), True)


def signed_group_sum(pk, edges):
    result = 0
    for _, index, sign, weight in edges:
        term = field_mul(weight, pk['powers'][index])
        result = (result + term) % P if sign == 0 else (result - term) % P
    return result


pk = read_pk()
secret_key = read_sk()
for name in ('a.ct', 'b.ct'):
    layers, edges = read_ct(name)
    by_layer = defaultdict(list)
    for edge in edges:
        by_layer[edge[0]].append(edge)
    print(name)
    for layer_id, seed in enumerate(layers):
        rows = by_layer[layer_id]
        R = prf_r(pk, secret_key, seed, False)
        signal = signed_group_sum(pk, rows[:8])
        plain = signed_group_sum(pk, rows) * pow(R, P - 2, P) % P
        n2 = all(
            signed_group_sum(pk, rows[8 + 2 * group:10 + 2 * group]) ==
            field_mul(R, noise_delta(pk, secret_key, seed, group, 0))
            for group in range(3)
        )
        n3 = all(
            signed_group_sum(pk, rows[14 + 3 * group:17 + 3 * group]) ==
            field_mul(R, noise_delta(pk, secret_key, seed, 3 + group, 1))
            for group in range(2)
        )
        r_squared = field_mul(R, R)
        r2_pairs = sum(
            signed_group_sum(pk, (rows[left], rows[right])) in (r_squared, (-r_squared) % P)
            for left in range(20) for right in range(left + 1, 20)
            if rows[left][2] != rows[right][2]
        )
        print(' layer=%d signal_is_R_times_plain=%s N2=%s N3=%s r2_pairs=%d plain=%032x' % (
            layer_id, signal == field_mul(R, plain), n2, n3, r2_pairs, plain))
