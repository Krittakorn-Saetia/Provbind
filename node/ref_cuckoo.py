"""Reference cuckoo filter (partial-key cuckoo hashing, Fan et al. 2014), for the CF tests.

i1 = h(x) mod m;  fp = f-bit fingerprint from a different part of h(x);  i2 = i1 XOR h(fp) mod m.
Theoretical false-positive rate ~ 2b / 2^f.  Buckets are stored in one compact array.
"""
import array, hashlib, random

def _h64(data: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "little")

class CuckooFilter:
    def __init__(self, n_items, bucket_size=4, fp_bits=16, load=0.9, max_kicks=500):
        m = 1
        while m * bucket_size * load < n_items:
            m <<= 1
        self.m, self.b, self.f, self.max_kicks = m, bucket_size, fp_bits, max_kicks
        self.mask = m - 1
        self.slots = array.array("H" if fp_bits <= 16 else "I", [0]) * (m * bucket_size)  # 0 = empty
        self.count = 0

    def _fp_i1(self, key: str):
        h = _h64(key.encode())
        fp = (h >> 32) & ((1 << self.f) - 1) or 1          # never 0 (0 marks an empty slot)
        return fp, h & self.mask

    def _alt(self, i, fp):
        return (i ^ _h64(fp.to_bytes(4, "little"))) & self.mask

    def _bucket(self, i):
        s = i * self.b
        return range(s, s + self.b)

    def add(self, key: str) -> bool:
        fp, i1 = self._fp_i1(key)
        for i in (i1, self._alt(i1, fp)):
            for s in self._bucket(i):
                if self.slots[s] == 0:
                    self.slots[s] = fp; self.count += 1; return True
        i = random.choice((i1, self._alt(i1, fp)))
        for _ in range(self.max_kicks):                     # evict and relocate
            s = random.choice(self._bucket(i))
            fp, self.slots[s] = self.slots[s], fp
            i = self._alt(i, fp)
            for s2 in self._bucket(i):
                if self.slots[s2] == 0:
                    self.slots[s2] = fp; self.count += 1; return True
        return False                                        # full: caller must handle (test CF-06)

    def __contains__(self, key: str) -> bool:
        fp, i1 = self._fp_i1(key)
        i2 = self._alt(i1, fp)
        sl = self.slots
        return any(sl[s] == fp for s in self._bucket(i1)) or any(sl[s] == fp for s in self._bucket(i2))

    def nbytes(self):
        return self.slots.itemsize * len(self.slots)
