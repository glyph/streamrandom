from streamrandom import new, dumps, loads

random = new("To Seed, Perchance, To Dream?")

print(random.randint(1, 20))

state = dumps(random)
print(state)
duplicate = loads(state)

for x in range(5):
    print(" = ".join(
        str(each.randint(1, 20))
        for each in [random, duplicate]
    ))
