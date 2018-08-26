import ecc
import model

# We will generate 3 rings
# All of them will be on G to keep it simple

# --------------------------------
# ring0 has 2 steps
# --------------------------------

ring0 = model.Ring(0)

# ring0:step0 has 2 keys
step0 = model.Step(0)
step0.keys = [
    model.KeyPair.random(ecc.G),
    model.KeyPair.random(ecc.G)
]

# ring0:step1 has 3 keys
step1 = model.Step(1)
step1.keys = [
    model.KeyPair.random(ecc.G, with_secret=True),
    model.KeyPair.random(ecc.G, with_secret=True),
    model.KeyPair.random(ecc.G, with_secret=True)
]

ring0.steps = [step0, step1]

# --------------------------------
# ring1 has 4 steps
# --------------------------------

ring1 = model.Ring(1)

# ring1:step0 has 1 keys
step0 = model.Step(0)
step0.keys = [
    model.KeyPair.random(ecc.G)
]

# ring1:step1 has 1 keys
step1 = model.Step(1)
step1.keys = [
    model.KeyPair.random(ecc.G, with_secret=True)
]

# ring1:step2 has 2 keys
step2 = model.Step(2)
step2.keys = [
    model.KeyPair.random(ecc.G),
    model.KeyPair.random(ecc.G)
]

# ring1:step3 has 1 keys
step3 = model.Step(3)
step3.keys = [
    model.KeyPair.random(ecc.G)
]

ring1.steps = [step0, step1, step2, step3]

# --------------------------------
# ring2 has 1 step
# --------------------------------

ring2 = model.Ring(2)

# ring1:step0 has 1 keys
step0 = model.Step(0)
step0.keys = [
    model.KeyPair.random(ecc.G, with_secret=True),
    model.KeyPair.random(ecc.G, with_secret=True),
    model.KeyPair.random(ecc.G, with_secret=True),
    model.KeyPair.random(ecc.G, with_secret=True)
]

ring2.steps = [step0]

rings_model = model.PirromeanRingsModel([ring0, ring1, ring2])
print(rings_model)

