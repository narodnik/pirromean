def verify(pirr):
    start = pirr.start_gate
    perform_verify(start)
    end = pirr.end_gate
    return end.challenge == start.challenge

def perform_verify(stargate):
    if stargate.challenge is not None:
        assert stargate.is_start
    else:
        # Wait for other inputs to finish
        if stargate.has_empty_input_witnesses():
            return
        stargate.compute_challenge()

    for portal in stargate.outputs:
        portal.derive_witness()

        perform_verify(portal.output_gate)

