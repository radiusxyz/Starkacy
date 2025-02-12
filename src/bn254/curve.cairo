// Basic definitions for the alt_bn128 elliptic curve.
// The curve is given by the equation
//   y^2 = x^3 + 3
// over the field Z/p for
// p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1 with u = 4965661367192848881
// const p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 =
// const p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

const P0 = 60193888514187762220203335;
const P1 = 27625954992973055882053025;
const P2 = 3656382694611191768777988;

// The following constants represent the size of the curve:
// n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
// const n = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const N0 = 0x39709143e1f593f0000001;
const N1 = 0x16da06056174a0cfa121e6;
const N2 = 0x30644e72e131a029b8504;

const N_LIMBS = 3;
const N_LIMBS_UNREDUCED = 2 * N_LIMBS - 1;
const DEGREE = N_LIMBS - 1;
const BASE = 2 ** 86;

// Non residue constants:
const NON_RESIDUE_E2_a0 = 9;
const NON_RESIDUE_E2_a1 = 1;
