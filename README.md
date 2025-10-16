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

## Usage

There are 3 main functions; `new`, `dumps`, and `loads`.

`new` will take a string seed, and give you a new object with all the same
methods as the stdlib's `Random` object.  Here is some code to roll a d20:

```python3
from streamrandom import new, dumps, loads
random = new("To Seed, Perchance, To Dream?")

print(random.randint(1, 20))
```

Auspiciously, this will begin with a natural 20.  Now, we can make a copy of
that random generator, like so:

```python3
state = dumps(random)
duplicate = loads(state)
```

and if we generate two streams of random numbers, like so:

```python3
for x in range(5):
    print(" = ".join(
        str(each.randint(1, 20))
        for each in [random, duplicate]
    ))
```

You should see the following output:

```python3
20
3 = 3
12 = 12
15 = 15
10 = 10
10 = 10
```

If you want to regenerate this output yourself, the relevant "state" string is
`"streamrandom:1:899de94aaec5060ea400f6f6b2e89d9d:2"`, so if you fire up a REPL
and do:

```python
from streamrandom import loads
random = loads("streamrandom:1:899de94aaec5060ea400f6f6b2e89d9d:2")
[random.randint(1, 20) for x in range(5)]
```

you should see the same numbers output as well:

```python3
[3, 12, 15, 10, 10]
```

Feel free to read the source code for some more esoteric internals, if you want
to try customizing your own cipher or getting your keystream from some other
source, but if this satisfies your use-case, that's it!

## Why not just `random.Random`?

The Python standard library's random number *interface* is incredibly
convenient for these sorts of applications; it has a number of different random
distributions that are interesting, as well as utilities like "shuffle" whose
applications are self-evident.

However, the Python standard library's seedable random number *implementation*
doesn't quite fit.

1. Its PRNG algorithm (Mersenne Twister) is not *quite* unpredictable: if you
   can observe its outputs, you can eventually [derive its
   inputs](https://en.wikipedia.org/wiki/Mersenne_Twister#Alternatives), which,
   in a game, might allow some players to cheat.

2. Its internal state to serialize produces an undocumented, opaque tuple
   containing about 4 kilobytes worth of integers, which is obnoxiously large
   to be transmitting around to synchronize related simulations, and documented
   as “an object capturing the current internal state of the generator”.  This
   does not provide great guidance for serializing and deserializing it
   faithfully; its method names of `getstate` and `setstate` imply that it is
   to be used with Pickle, which is also not a [great
   way](https://us.pycon.org/2014/schedule/presentation/155/) to communicate
   sensitive state.  By contrast, `streamrandom`'s serialized form, as you can
   see above, is quite compact.

The unpredictable, secure alternative in `SystemRandom` cannot be seeded at
all.

## More use-cases

One use-case for this is video games.  Many games
([Minecraft](https://www.minecraft.net/) and the
[`.hack//`](https://en.wikipedia.org/wiki/.hack_(video_game_series)) series
being two of my favorites) use pseudo-random procedural generation to great
effect.

Testing is also another one.  You may want a truly random, unbiased ordering
for your test suite, but also want to be able to reliably get that same
ordering on a different machine for reproducing some issue.

