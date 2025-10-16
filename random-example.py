from streamrandom import new, dumps, loads

random = new("To Seed, Perchance, To Dream?")

state = dumps(random)
duplicate = loads(state)
print(random.randint(1, 20))
for x in range(5):
    print(" = ".join(
        str(each.randint(1, 20))
        for each in [random, duplicate]
    ))
