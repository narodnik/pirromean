import ecc
import json
import pprint

def load(filename):
    with open(filename) as infile:
        data = json.load(infile)
        rings_model = PirromeanRingsModel.load_json(data)
    return rings_model

def save(filename, rings_model):
    with open(filename, "w") as outfile:
        json.dump(rings_model.to_json(), outfile)

class PirromeanRingsModel:

    def __init__(self, rings):
        self.rings = rings

    @classmethod
    def load_json(cls, json):
        rings = [Ring.load_json(ring_json)
                 for ring_json in json["rings"]]
        return cls(rings)

    def to_json(self):
        return {"rings": [ring.to_json() for ring in self.rings]}

    def __str__(self):
        return pprint.pformat(self.to_json(), indent=2)

    def signing_indexes(self):
        return [ring.signing_step_index() for ring in self.rings]

class Ring:

    def __init__(self, index):
        self.steps = []
        self.index = index

    @classmethod
    def load_json(cls, json):
        self = cls(json["ring_index"])
        self.steps = [Step.load_json(step_json)
                      for step_json in json["steps"]]
        return self

    def to_json(self):
        return {"ring_index": self.index,
                "steps": [step.to_json() for step in self.steps]}

    def signing_step_index(self):
        assert [step for step in self.steps if step.is_signing_step()]
        for step in self.steps:
            if step.is_signing_step():
                return step.index
        # Impossible

class Step:

    def __init__(self, index):
        self.keys = []
        self.index = index

    @classmethod
    def load_json(cls, json):
        self = cls(json["index"])
        self.keys = [KeyPair.load_json(key_json)
                     for key_json in json["keys"]]
        return self

    def to_json(self):
        return {"index": self.index,
                "keys": [key.to_json() for key in self.keys]}

    def is_signing_step(self):
        return all(key.secret is not None for key in self.keys)

class KeyPair:

    def __init__(self, public, secret=None):
        self.public = public
        self.secret = secret

    @classmethod
    def random(cls, generator, with_secret=False):
        self = cls(None, None)
        secret = ecc.random_scalar()
        if with_secret:
            self.secret = secret
        self.public = generator * secret
        return self

    @classmethod
    def load(cls, public_data, secret_data=None):
        self = cls(None, None)
        if secret_data is not None:
            self.secret = ecc.deserialize_scalar(secret_data)
        self.public = ecc.deserialize_point(public_data)
        return self

    @classmethod
    def load_json(cls, json):
        return cls.load(json["public"], json["secret"])

    @property
    def public_hex(self):
        return self.public_bytes.hex()
    @property
    def public_bytes(self):
        return ecc.serialize_point(self.public)

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
        return {"public": self.public_hex, "secret": self.secret_hex}

    def __str__(self):
        result = self.public_hex
        if self.secret:
            result += ": %s" % self.secret_hex
        return result

