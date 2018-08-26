import ecc
import pprint

class PirromeanRingsModel:

    def __init__(self, rings):
        self.rings = rings

    def to_json(self):
        return {"rings": [ring.to_json() for ring in self.rings]}

    def __str__(self):
        return pprint.pformat(self.to_json(), indent=2)

class Ring:

    def __init__(self, index):
        self.steps = []
        self.index = index

    def to_json(self):
        return {"ring_index": self.index,
                "steps": [step.to_json() for step in self.steps]}

class Step:

    def __init__(self, index):
        self.keys = []
        self.index = index

    def to_json(self):
        return {"index": self.index,
                "keys": [key.to_json() for key in self.keys]}

class KeyPair:

    def __init__(self, public, secret=None):
        self.public = public
        self.secret = secret

    @classmethod
    def random(cls, generator, with_secret=False):
        key = cls(None, None)
        secret = ecc.random_scalar()
        if with_secret:
            key.secret = secret
        key.public = generator * secret
        return key

    @classmethod
    def load(cls, public_data, secret_data=None):
        key = cls(None, None)
        if secret_data is not None:
            key.secret = ecc.deserialize_scalar(secret_data)
        key.public = ecc.deserialize_point(public_data)
        return key

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

