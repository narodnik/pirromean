import ecc
import model

gate_0 = model.Stargate(0)
gate_1 = model.Stargate(1)
gate_2 = model.Stargate(2)
gate_3 = model.Stargate(3)

gate_0.is_start = True
gate_3.is_end = True

portal_a = model.Portal(
    [ model.KeyPair.random(ecc.G, with_secret=True) ]
)

portal_b = model.Portal(
    [ model.KeyPair.random(ecc.G, with_secret=True) ]
)

portal_c = model.Portal(
    [ model.KeyPair.random(ecc.G, with_secret=True) ]
)

portal_d = model.Portal(
    [ model.KeyPair.random(ecc.G, with_secret=True) ]
)

portal_a.link(gate_0, gate_2)

portal_b.link(gate_0, gate_1)
portal_c.link(gate_1, gate_2)

portal_d.link(gate_2, gate_3)

pirr = model.PirromeanModel(
    [ gate_0, gate_1, gate_2, gate_3 ],
    [ portal_a, portal_b, portal_c, portal_d ]
)
model.save("pirr.model", pirr)
print("Saved model to 'pirr.model'.")

