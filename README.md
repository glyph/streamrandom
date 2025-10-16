# StreamRandom

Sometimes you want randomness that is *unpredictable*, but still *repeatable*,
and derived from a *known*, *human memorable* start point.

Before I continue: for cryptographic randomness, such a source of randomness is
totally unsuitable.  Cryptographic randomness must be, above all,
unpredictable, and repeatability is the enemy of that.  It should come from the
operating system so that cryptographic techniques for ensuring
unpredictablility without knowing the internal state are mixed with randomness
derived from hardware to determine that initial state.  So if you're looking to
do something with the Python "random" object's interface that is *in any way*
security-relevant, you want
[`random.SystemRandom`](https://docs.python.org/3.14/library/random.html#random.SystemRandom);
if you just want random bytes, you want
[`os.urandom`](https://docs.python.org/3.14/library/os.html#os.urandom).

Now that we have accepted that you will *never, ever* use this module for
security purposes: sometimes it's handy to have the type of randomness I'm
describing.

One use-case for this is video games.  Many games
([Minecraft](https://www.minecraft.net/) and the
[`.hack//`](https://en.wikipedia.org/wiki/.hack_(video_game_series)) series
being two of my favorites) use pseudo-random procedural generation to great
effect.

Testing is also another one.

The Python standard library's random number *interface* is incredibly
convenient for these sorts of applications; it has a number of different random
distributions that are interesting, as well as utilities like "shuffle" whose
applications are self-evident.

However, the Python standard library's seedable random number *implementation*
doesn't quite fit.  Its PRNG algorithm (Mersenne Twister) is not quite
unpredictable: if you can observe its outputs, you can eventually [derive its
inputs](https://en.wikipedia.org/wiki/Mersenne_Twister#Alternatives), which, in
a game, might allow some players to cheat.  The unpredictable, secure
alternative in `SystemRandom` cannot be seeded at all.
