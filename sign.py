def sign(pirr):
    end = pirr.end_gate
    get_challenge(end)

    start = pirr.start_gate
    start.challenge = end.challenge

    join_wormholes(start)

def get_challenge(stargate):
    if stargate.challenge is not None:
        return stargate.challenge
    if stargate.is_start:
        raise Exception("invalid graph")
    [compute_witness(portal) for portal in stargate.inputs]
    stargate.compute_challenge()
    return stargate.challenge

def compute_witness(portal):
    if portal.is_signing_portal():
        perform_protocol(portal)
    else:
        simulate_witness(portal)

def simulate_witness(portal):
    get_challenge(portal.input_gate)
    portal.create_random_responses()
    portal.derive_witness()

def perform_protocol(portal):
    portal.random_witness()

#########

def join_wormholes(stargate):
    if stargate.challenge is None:
        stargate.compute_challenge()

    for portal in stargate.outputs:
        if portal.is_signing_portal():
            portal.compute_valid_responses()
        else:
            portal.create_random_responses()
            portal.derive_witness()

            join_wormholes(portal.output_gate)

#########

if __name__ == "__main__":
    import model
    pirr = model.load("pirr.model")
    sign(pirr)
    clean = pirr.clone_public()
    print(clean)

