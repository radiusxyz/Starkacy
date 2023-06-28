from unicodedata import decimal
from src.starkcurve import _STARKCURVE, G, Q
from src.bn128 import BN128, G_bn128, Q_bn128
from src.fast_pedersen_starkware import *

from starkware.crypto.signature.signature import FIELD_PRIME
from starkware.cairo.common.poseidon_hash import poseidon_hash, poseidon_hash_many

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
    def prove(self, k_u, k_s):
        
        # user key and nonce
        r_u = number.getRandomRange(1, BN128.q - 1)
        # r_u = 17349940748761793203113299844175377003983001038161293476542894180571014896327
        R_u = r_u * G_bn128
        P_u = k_u * G_bn128
        m = 1234

        # sequencer key and nonce
        r_s = number.getRandomRange(1, BN128.q - 1)
        # r_s = 17349940748761793203113299844175377003983001038161293476542894180571014896327
        R_s = r_s * G_bn128
        P_s = k_s * G_bn128

        # challenge
        R = R_u + R_s
        # l = poseidon_hash(poseidon_hash(P_u.x, P_u.y), poseidon_hash(P_s.x, P_s.y))
        # w_u = poseidon_hash(l, poseidon_hash(P_u.x, P_u.y))
        # w_s = poseidon_hash(l, poseidon_hash(P_s.x, P_s.y))
        l_list = [P_u.x, P_u.y, P_s.x, P_s.y]
        l = poseidon_hash_many(l_list)
        w_u_list = [l, P_u.x, P_u.y]
        w_u = poseidon_hash_many(w_u_list)
        w_s_list = [l, P_s.x, P_s.y]
        w_s = poseidon_hash_many(w_s_list)
        X = w_u * P_u + w_s * P_s
        i = 1234

        poseidon_list = [R.x, R.y, X.x, X.y, m, i]
        e = poseidon_hash_many(poseidon_list)

        # partial sig
        s_u = r_u + k_u * w_u * e
        s_s = r_s + k_s * w_s * e
        s = s_u + s_s

        return P_s, P_u ,s, R, i, m

    # off-chain verification for testing
    def verify(self, P_s, P_u, s, R, i, m):
        # l = poseidon_hash(poseidon_hash(P_u.x, P_u.y), poseidon_hash(P_s.x, P_s.y))
        # w_u = poseidon_hash(l, poseidon_hash(P_u.x, P_u.y))
        # w_s = poseidon_hash(l, poseidon_hash(P_s.x, P_s.y))
        l_list = [P_u.x, P_u.y, P_s.x, P_s.y]
        l = poseidon_hash_many(l_list)
        print('hash test: ', poseidon_hash(P_u.x % FIELD_PRIME, P_u.y % FIELD_PRIME))
        w_u_list = [l, P_u.x, P_u.y]
        w_u = poseidon_hash_many(w_u_list)
        w_s_list = [l, P_s.x, P_s.y]
        w_s = poseidon_hash_many(w_s_list)
        X = w_u * P_u + w_s * P_s

        poseidon_list = [R.x, R.y, X.x, X.y, m, i]
        e = poseidon_hash_many(poseidon_list)

        left = s * G_bn128
        right = R + e * X
        assert left == right
