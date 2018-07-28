"""
Sometimes you want randomness that is I{unpredictable}, but still
I{repeatable}, and derived from a I{known}, I{human memorable} start point.

Before I continue: for cryptographic randomness, such a source of randomness is
totally unsuitable.  Cryptographic randomness must be, above all,
unpredictable, and repeatability is the enemy of that.  It should come from the
operating system so that cryptographic techniques for ensuring
unpredictablility without knowing the internal state are mixed with randomness
derived from hardware to determine that initial state.  So if you're looking to
do something with the Python "random" object's interface that is I{in any way}
security-relevant, you want L{random.SystemRandom}; if you just want random
bytes, you want L{os.urandom}.

Now that we have accepted that you will I{never, ever} use this module for
security purposes: sometimes it's handy to have the type of randomness I'm
describing.

One use-case for this is video games.  Many games (Minecraft and the .hack//
series being two of my favorites) use pseudo-random procedural generation to
great effect.  Testing is also another one.

The Python standard library's random number I{interface} is incredibly
convenient for these sorts of applications; it has a number of different random
distributions that are interesting, as well as utilities like "shuffle" whose
applications are self-evident.

However, the Python standard library's random number I{implementation} doesn't
quite fit.  First, its PRNG algorithm (Mersenne Twister) is not quite
unpredictable: if you can observe its outputs, you can eventually U{derive its
inputs <https://en.wikipedia.org/wiki/Mersenne_Twister#Alternatives>}, which,
in a game, might allow some players to cheat.  On Python 2.7 it isn't even
repeatable, when used with human-memorable values; due to an U{unfortunate bug
<https://bugs.python.org/issue27706>}, you have to convert your strings into
integers yourself somehow before they're usable as stable seeds.

MIT license, (C) glyph; if it breaks you can keep both halves.
"""

from __future__ import unicode_literals

from random import Random, BPF, RECIP_BPF
from uuid import UUID
from unicodedata import normalize

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.utils import int_from_bytes, int_to_bytes

from publication import publish

__all__ = ["StreamRandom", "CipherStream", "stream_from_seed"]

__version__ = "0.0.1"


def _bytes_for_bits(bits):
    """
    How many bytes do I need to read to get the given number of bits of
    entropy?
    """
    bits_per_byte = 8
    return (bits + (bits_per_byte - 1)) // bits_per_byte


_uint128max = (1 << 128) - 1


def _bits(*ns):
    r = 0
    for n in ns:
        r |= 1 << (128 - (n + 1))
    return r


_offBits = _uint128max ^ _bits(48, 50, 51, 65)
_onBits = _bits(49, 64)


class StreamRandom(Random, object):
    """
    A L{StreamRandom} converts a stream of bytes into an object that has the
    same useful methods as a standard library L{random.Random}, plus its own
    C{uuid4} method.
    """

    def __init__(self, stream):
        """
        Create a L{StreamRandom}.

        @param stream: A file-like object.
        """
        # No super(); skip over the call to .seed() in Random.__init__.
        self._stream = stream

    def getrandbits(self, k):
        """
        Get some random bits.  This is the primitive upon which all
        higher-level functions are built.

        @return: an integer containing C{k} random bits
        @rtype: L{int} or L{long}
        """
        if k != int(k):
            raise TypeError("k must be an integer")
        if not k > 0:
            raise ValueError("k must be positive")
        octet_count = _bytes_for_bits(k)
        octets = self._stream.read(octet_count)
        if len(octets) != octet_count:
            raise RuntimeError("out of entropy")
        x = int_from_bytes(octets, byteorder="big")
        return x >> (octet_count * 8 - k)

    def seed(self, a=None):
        """
        Create a new stream from the given seed.
        """
        raise NotImplementedError(
            "To re-seed, create a new StreamRandom with a new stream."
        )

    def random(self):
        """
        Get the next random number in the range [0.0, 1.0).
        """
        return self.getrandbits(BPF) * RECIP_BPF

    def jumpahead(self, n):
        """
        Jump ahead in the stream as if C{random} had been called C{n} times.
        """
        self._stream.seek(n * 7, 1)

    def getstate(self):
        """
        Get the internal state necessary to serialize this object.
        """
        return self._stream

    def setstate(self, state):
        """
        Unserialize this object from the given state, previously serialized by
        C{getstate}.
        """
        self._stream = state

    def uuid4(self):
        """
        Bonus method!  Generate UUID4s from a deterministic source of
        randomness.
        """
        integer = self.randint(0, _uint128max)
        return UUID(int=((integer & _offBits) | _onBits))


class CipherStream(object):
    """
    A seekable stream of pseudo-random data based on a block cipher in CTR mode
    """

    _remaining = b""

    def __init__(self, algorithm):
        """
        Create a keystream from an algorithm, and a function returning a mode
        for that algorithm at a given block.

        @param algorithm: a pyca/cryptography block cipher.  block_size minimum
            of 128 recommended, due to the internal usage of CTR.
        """
        self._algorithm = algorithm
        self._octets_per_block = self._algorithm.block_size // 8
        self._null_block = int_to_bytes(0, self._octets_per_block)
        self.seek(0)

    def seek(self, n, whence=0):
        if whence == 0:
            goal = n
        elif whence == 1:
            goal = self._pos + n
        else:
            raise ValueError("SEEK_END not supported; keystreams are infinite.")

        closest_block, beyond = divmod(goal, self._octets_per_block)
        self._remaining = b""
        self._pos = closest_block * self._octets_per_block
        self._encryptor = Cipher(
            self._algorithm,
            CTR(int_to_bytes(closest_block, self._octets_per_block)),
            backend=default_backend(),
        ).encryptor()
        self.read(beyond)

    def tell(self):
        return self._pos

    def read(self, n):
        self._pos += n
        result = b""
        remaining = self._remaining
        while n:
            if not remaining:
                blocks, remainder = divmod(n, self._octets_per_block)
                remaining += self._encryptor.update(
                    self._null_block * (blocks + int(bool(remainder)))
                )
            more, remaining = remaining[:n], remaining[n:]
            result += more
            n -= len(more)
        self._remaining = remaining
        return result


def stream_from_seed(seed, version=1):
    """
    Create a L{CipherStream}

    @param seed: An arbitrary string.
    @type seed: unicode text
    """
    if version != 1:
        raise NotImplementedError("only one version exists")
    seed = normalize("NFKD", seed)
    hasher = Hash(SHA256(), backend=default_backend())
    hasher.update(seed)
    return CipherStream(AES(hasher.finalize()[: AES.block_size // 8]))


publish()
