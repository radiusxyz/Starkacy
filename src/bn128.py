# a, b, p are parameters of the Weierstrass form of the Stark-friendly elliptic curve
# https://docs.starkware.co/starkex-v4/crypto/stark-curve

# Q is order of the Stark-friendly elliptic curve
#https://crypto.stackexchange.com/questions/95666/how-to-find-out-what-the-order-of-the-base-point-of-the-elliptic-curve-is

# (gx, gy) is the generated point used in ECDSA scheme for the Stark-friendly elliptic curve
# (hx, hy) is generated offline using a cryptographic random number and the (gx, gy)

from fastecdsa.curve import Curve
from fastecdsa.point import Point

Q_bn128 = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# P = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
# N = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
N = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

# elliptic curve
A = 0
B = 2
# generator point on G1
Gx = P - 1
Gy = 1

BN128 = Curve(
    "BN128",
    P,
    A,
    B,
    N,
    Gx,
    Gy,
)

# Generator of the _STARKCURVE
G_bn128 = Point(Gx, Gy, BN128)