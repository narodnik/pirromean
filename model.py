import ecc

class PirromeanData:

    def __init__(self):
        self.rings = []

class Ring:

    def __init__(self, index):
        self.steps = []
        self.index = index

class Step:

    def __init__(self, index):
        self.keys = []
        self.index = index

class KeyPair:

    def __init__(self, public, secret=None):
        self.public = public
        self.secret = secret

    @classmethod
    def random(cls, generator):
        key = cls(None, None)
        key.secret = ecc.random_scalar()
        key.public = generator * key.secret
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
        return self.secret_bytes.hex()
    @property
    def secret_bytes(self):
        return ecc.serialize_scalar(self.secret)

    def __str__(self):
        result = self.public_hex
        if self.secret:
            result += ": %s" % self.secret_hex
        return result

