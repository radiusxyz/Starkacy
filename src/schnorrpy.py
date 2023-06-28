from unicodedata import decimal
from src.starkcurve import _STARKCURVE, G, Q
from src.bn128 import BN128, G_bn128, Q_bn128
from src.fast_pedersen_starkware import *

from starkware.crypto.signature.signature import FIELD_PRIME
from starkware.cairo.common.poseidon_hash import poseidon_hash

# Random number is generated without considering the security, maybe changed later
from Crypto.Random import random
from Crypto.Util import number

class SchnorrSignature:
    def prove(self, secret):
        alpha = number.getRandomRange(1, _STARKCURVE.q - 1)

        alpha_G = alpha * G
        x = alpha_G.x
        y = alpha_G.y
        
        c = pedersen_hash(x, y)
        
        response = (alpha + c * secret) % Q
        public_key = secret * G
        return alpha_G, response, public_key

    # off-chain verification for testing
    def verify(self, alpha_G, response, public_key):
        x = alpha_G.x
        y = alpha_G.y
        challenge = pedersen_hash(x, y)
        _R = response * G
        _Rprime = alpha_G  + challenge * public_key
        assert _R == _Rprime

class SchnorrSignatureBN254:
    def prove(self, secret):
        alpha = number.getRandomRange(1, BN128.q - 1)
        alpha = 17349940748761793203113299844175377003983001038161293476542894180571014896327

        alpha_G = alpha * G_bn128
        
        x = alpha_G.x
        y = alpha_G.y
        
        c = poseidon_hash(x , y)
        
        response = (alpha + c * secret) % Q_bn128
        public_key = secret * G_bn128
        return alpha_G, response, public_key

    # off-chain verification for testing
    def verify(self, alpha_G, response, public_key):
        x = alpha_G.x
        y = alpha_G.y
        challenge = poseidon_hash(x , y)

        _R = response * G_bn128
        _Rprime = alpha_G + challenge * public_key
        assert _R == _Rprime
