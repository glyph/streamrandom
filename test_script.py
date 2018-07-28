import json

for rnd in game_random("hello, world"), game_random():
    print("seed...")
    for each in range(10):
        print(rnd.random())
    import json
    saved = json.dumps(save(rnd))
    rnd2 = load(json.loads(saved))
    for each in range(10):
        print(rnd.random())
        print(rnd2.random())
