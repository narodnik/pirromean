import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import string_to_number, number_to_string

G = SECP256k1.generator
    
def string_to_scalar(s):
    n = string_to_number(s)
    assert 0 <= n < SECP256k1.order
    return n

def random_scalar():
    return ecdsa.util.randrange(SECP256k1.order)

def serialize_point(p): # SEC compressed format
    return bytes([(p.y() & 1) + 2]) + number_to_string(p.x(), SECP256k1.order)

def get_y_coord_from_x(x, odd=True):
    curve = curve_secp256k1
    _p = curve.p()
    _a = curve.a()
    _b = curve.b()
    for offset in range(128):
        Mx = x + offset
        My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
        My = pow(My2, (_p + 1) // 4, _p)
        if curve.contains_point(Mx, My):
            if odd == bool(My & 1):
                return My
            return _p - My
    raise Exception('ECC_YfromX: No Y found')

def ser_to_point(ser: bytes) -> (int, int):
    if ser[0] not in (0x02, 0x03, 0x04):
        raise ValueError('Unexpected first byte: {}'.format(ser[0]))
    if ser[0] == 0x04:
        return string_to_number(ser[1:33]), string_to_number(ser[33:])
    x = string_to_number(ser[1:])
    return x, get_y_coord_from_x(x, ser[0] == 0x03)

def ser_to_python_ecdsa_point(ser: bytes) -> ecdsa.ellipticcurve.Point:
    x, y = ser_to_point(ser)
    return Point(curve_secp256k1, x, y, SECP256k1.order)

def deserialize_point(data):
    if type(data) == str:
        data = bytes.fromhex(data)
    return ser_to_python_ecdsa_point(data)

def serialize_scalar(scalar):
    return number_to_string(scalar, SECP256k1.order)

def deserialize_scalar(data):
    if type(data) == str:
        data = bytes.fromhex(data)
    return string_to_number(data)

