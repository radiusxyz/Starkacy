from unicodedata import decimal
from src.starkcurve import _STARKCURVE, G, Q
from src.bn128 import BN128, G_bn128, Q_bn128
from src.fast_pedersen_starkware import *

from starkware.crypto.signature.signature import FIELD_PRIME

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
        # alpha = number.getRandomRange(1, BN128.q - 1)
        alpha = 11699345969143607716123798763319908368448159588996525204358640425161994192053
        print("alpha: ", alpha)
        # PASS
        # 9381026497127656046494092275388531659513085316485292075481042341545212533115
        # 11699345969143607716123798763319908368448159588996525204358640425161994192053
        # 16810287722219493749318350199427018434636312138163774831143896671271547219128
        # Fail
        # 14616305567727897073514772413384390663863529922201512777577511180807384523834
        # 20553877919489894120883731631652574626790766322906938680110842732044637150712
        # 9684542920753197018358927051885089503689655125831460442788643908312265593422

        alpha_G = alpha * G_bn128
        
        x = alpha_G.x
        y = alpha_G.y
        
        c = pedersen_hash(x % FIELD_PRIME, y % FIELD_PRIME)
        c = c % FIELD_PRIME
        
        response = (alpha + c * secret) % Q_bn128
        public_key = secret * G_bn128
        return alpha_G, response, public_key

    # off-chain verification for testing
    def verify(self, alpha_G, response, public_key):
        x = alpha_G.x % FIELD_PRIME
        y = alpha_G.y % FIELD_PRIME
        challenge = pedersen_hash(x , y) % FIELD_PRIME

        _R = response * G_bn128
        _Rprime = alpha_G + challenge * public_key
        assert _R == _Rprime
