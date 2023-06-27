// BASE_POINT is the generator point used in the ECDSA scheme
// https://docs.starkware.co/starkex-v4/crypto/stark-curve

// To generate BASE_BLINDING_POINT, a cryptographic random number is generated
// BASE_BLINDING_POINT is the result of elliptic curve scalar multiplication of
// "cryptographic number" and "BASE_POINT", which the operation is done as offline

// Note that the generated number is less than the order of the starkcurve:
// 3618502788666131213697322783095070105526743751716087489154079457884512865583
// The order of the elliptic curve is found thanks to:
// https://crypto.stackexchange.com/questions/95666/how-to-find-out-what-the-order-of-the-base-point-of-the-elliptic-curve-is

// MINUS_1 is calculated by subtracting -1 from the order of STARKCURVE

const BASE_POINT_X = 874739451078007766457464989774322083649278607533249481151382481072868806602;
const BASE_POINT_Y = 152666792071518830868575557812948353041420400780739481342941381225525861407;
const BASE_BLINDING_POINT_X = 1644404348220522245795652770711644747389835183387584438047505930708711545294;
const BASE_BLINDING_POINT_Y = 3418409665108082357574218324957319851728951500117497918120788963183493908527;
const MINUS_1 = 3618502788666131213697322783095070105526743751716087489154079457884512865582;

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