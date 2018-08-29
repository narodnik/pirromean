import ecc
import hashlib
import json
import pprint

flatten = lambda l: [item for sublist in l for item in sublist]

def pirrhash(witness):
    value = b""
    for witness_ in flatten(witness):
        value += witness_.commit_bytes
    digest = hashlib.sha256(value).digest()
    return ecc.string_to_scalar(digest)

def load(filename):
    with open(filename) as infile:
        data = json.load(infile)
        pirr = PirromeanModel.load_json(data)
    return pirr

def save(filename, pirr):
    with open(filename, "w") as outfile:
        json.dump(pirr.to_json(), outfile, indent=2)

class PirromeanModel:

    def __init__(self, gates, portals):
        self.gates = gates
        self.portals = portals

    def clone_public(self):
        gates = [gate.clone_public() for gate in self.gates]
        gates.sort(key=lambda gate: gate.index)
        portals = [portal.clone_public(gates) for portal in self.portals]
        gates[0].challenge = self.gates[0].challenge
        return PirromeanModel(gates, portals)

    @classmethod
    def load_json(cls, json):
        gates = [Stargate.load_json(stargate_json)
                 for stargate_json in json["stargates"]]
        gates.sort(key=lambda gate: gate.index)

        portals = [Portal.load_json(portal_json, gates)
                   for portal_json in json["portals"]]
        self = cls(gates, portals)
        return self

    def to_json(self):
        return {"stargates": [gate.to_json() for gate in self.gates],
                "portals": [portal.to_json() for portal in self.portals]}

    @property
    def start_gate(self):
        gate = [gate for gate in self.gates if gate.is_start]
        assert len(gate) == 1
        return gate[0]

    @property
    def end_gate(self):
        gate = [gate for gate in self.gates if gate.is_end]
        assert len(gate) == 1
        return gate[0]

    def __str__(self):
        return pprint.pformat(self.to_json(), indent=2)

class Stargate:

    def __init__(self, index):
        self._index = index
        self.challenge = None

        self.inputs = []
        self.outputs = []

        self.is_start = False
        self.is_end = False

    def clone_public(self):
        stargate = Stargate(self.index)
        stargate.is_start = self.is_start
        stargate.is_end = self.is_end
        return stargate

    def add_input(self, portal):
        self.inputs.append(portal)
    def add_output(self, portal):
        self.outputs.append(portal)

    def has_empty_input_witnesses(self):
        input_witnesses = [input.witness for input in self.inputs]
        return any(witness.commit is None
                   for witness in flatten(input_witnesses))

    def compute_challenge(self):
        witness = [portal.witness for portal in self.inputs]
        self.challenge = pirrhash(witness)

    @property
    def index(self):
        return self._index

    @classmethod
    def load_json(cls, json):
        self = cls(json["index"])
        self.challenge = json["challenge"]
        self.is_start = json["is_start"]
        self.is_end = json["is_end"]
        return self

    def to_json(self):
        return {"index": self.index, "challenge": self.challenge,
                "is_start": self.is_start, "is_end": self.is_end}

    def __str__(self):
        return pprint.pformat(self.to_json(), indent=2)

class Portal:

    def __init__(self, keys):
        self.keys = keys
        self.witness = [Witness() for _ in keys]
        self.responses = []

        self.input_gate = None
        self.output_gate = None

    def clone_public(self, new_stargates):
        keys = [key.clone_public() for key in self.keys]
        portal = Portal(keys)
        portal.responses = self.responses[:]
        input_gate = new_stargates[self.input_gate.index]
        output_gate = new_stargates[self.output_gate.index]
        portal.link(input_gate, output_gate)
        return portal

    def link(self, input_gate, output_gate):
        self.input_gate = input_gate
        self.output_gate = output_gate

        self.input_gate.add_output(self)
        self.output_gate.add_input(self)

    def to_json(self):
        return {"keys": [key.to_json() for key in self.keys],
                "input": self.input_gate.index,
                "output": self.output_gate.index,
                "witness": [witness.to_json() for witness in self.witness],
                "response": self.responses}

    @classmethod
    def load_json(cls, json, gates):
        keys = [KeyPair.load_json(key_json)
                for key_json in json["keys"]]
        self = cls(keys)
        self.witness = [Witness.load_json(witness_json)
                        for witness_json in json["witness"]]
        assert len(self.witness) == len(keys)
        input_gate = gates[json["input"]]
        output_gate = gates[json["output"]]
        self.link(input_gate, output_gate)
        return self

    def is_signing_portal(self):
        return all(key.secret is not None for key in self.keys)

    def create_random_responses(self):
        self.responses = [ecc.random_scalar() for _ in self.keys]

    def derive_witness(self):
        assert self.input_gate.challenge is not None
        challenge = self.input_gate.challenge

        for response, keypair, witness in zip(self.responses, self.keys,
                                              self.witness):
            witness.commit = response * keypair.generator + \
                             (-challenge) * keypair.public

    def random_witness(self):
        for keypair, witness in zip(self.keys, self.witness):
            witness.random(keypair.generator)

    #############

    def compute_valid_responses(self):
        assert self.input_gate.challenge is not None
        challenge = self.input_gate.challenge

        self.responses = []
        for keypair, witness in zip(self.keys, self.witness):
            assert witness.secret is not None
            assert keypair.secret is not None
            response = (witness.secret + challenge * keypair.secret) % \
                ecc.SECP256k1.order
            self.responses.append(response)

            self._debug_verify_witness(keypair, witness, response, challenge)

    def _debug_verify_witness(self, keypair, witness, response, challenge):
        commit = response * keypair.generator + (-challenge) * keypair.public
        assert witness.commit == keypair.generator * witness.secret
        assert witness.commit == commit

    def __str__(self):
        return pprint.pformat(self.to_json(), indent=2)

class Witness:

    def __init__(self):
        self.secret = None
        self.commit = None

    def reset(self):
        self.secret = None
        self.commit = None

    def random(self, generator):
        self.secret = ecc.random_scalar()
        self.commit = generator * self.secret

    @property
    def secret_hex(self):
        if self.secret is None:
            return None
        return self.secret_bytes.hex()
    @property
    def secret_bytes(self):
        if self.secret is None:
            return None
        return ecc.serialize_scalar(self.secret)

    @property
    def commit_hex(self):
        if self.commit is None:
            return None
        return self.commit_bytes.hex()
    @property
    def commit_bytes(self):
        if self.commit is None:
            return None
        return ecc.serialize_point(self.commit)

    @classmethod
    def load(cls, commit_data):
        self = cls()
        if commit_data is not None:
            self.commit = ecc.deserialize_point(commit_data)
        return self

    @classmethod
    def load_json(cls, json):
        return cls.load(json["commit"])

    def to_json(self):
        result = {"commit": self.commit_hex}
        if self.secret is not None:
            result["secret"] = self.secret_hex
        return result

    def __str__(self):
        return pprint.pformat(self.to_json(), indent=2)

class KeyPair:

    def __init__(self, public, generator, secret=None):
        self.public = public
        self.generator = generator
        self.secret = secret

    def clone_public(self):
        return KeyPair(self.public, self.generator)

    @classmethod
    def random(cls, generator, with_secret=False):
        self = cls(None, None)
        secret = ecc.random_scalar()
        if with_secret:
            self.secret = secret
        self.generator = generator
        self.public = generator * secret
        return self

    @classmethod
    def load(cls, public_data, generator_data, secret_data=None):
        self = cls(None, None)
        if secret_data is not None:
            self.secret = ecc.deserialize_scalar(secret_data)
        self.generator = ecc.deserialize_point(generator_data)
        self.public = ecc.deserialize_point(public_data)
        return self

    @classmethod
    def load_json(cls, json):
        return cls.load(json["public"], json["generator"], json["secret"])

    @property
    def public_hex(self):
        return self.public_bytes.hex()
    @property
    def public_bytes(self):
        return ecc.serialize_point(self.public)

    @property
    def generator_hex(self):
        return self.generator_bytes.hex()
    @property
    def generator_bytes(self):
        return ecc.serialize_point(self.generator)

    @property
    def secret_hex(self):
        if self.secret is None:
            return None
        return self.secret_bytes.hex()
    @property
    def secret_bytes(self):
        if self.secret is None:
            return None
        return ecc.serialize_scalar(self.secret)

    def to_json(self):
        return {"public": self.public_hex, "generator": self.generator_hex,
                "secret": self.secret_hex}

    def __str__(self):
        result = self.public_hex
        if self.secret:
            result += ": %s" % self.secret_hex
        return result

