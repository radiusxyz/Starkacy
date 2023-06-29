from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import assert_on_curve, ec_add, ec_double, ec_op
from src.math_utils import ec_mul, felt_to_uint256, uint256_to_felt
from src.constants import BASE_POINT_X, BASE_POINT_Y
from starkware.cairo.common.cairo_builtins import EcOpBuiltin, BitwiseBuiltin, HashBuiltin, PoseidonBuiltin
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash, poseidon_hash_many
from starkware.cairo.common.uint256 import Uint256, uint256_unsigned_div_rem, split_64
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.math import split_felt

from starkware.cairo.common.cairo_secp.bigint import BASE, BigInt3, bigint_mul, nondet_bigint3, uint256_to_bigint, bigint_to_uint256
from src.bn254.curve import N0, N1, N2, P0, P1, P2
from src.bn254.g1 import G1Point, G1PointFull, g1

const FIELD_PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481;

func verify_schnorr_signature{output_ptr : felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*}(alpha_G : EcPoint, response : felt, public_key : EcPoint){
    alloc_locals;

    assert_on_curve(alpha_G);

    local G: EcPoint = EcPoint(BASE_POINT_X, BASE_POINT_Y);
    assert_on_curve(G);

    let (_challenge) = hash2{hash_ptr=pedersen_ptr}(alpha_G.x, alpha_G.y);

    let (R) = ec_mul(G, response);
    let (c_k) = ec_mul(public_key, _challenge);
    let (R_) = ec_add(alpha_G, c_k);

    assert R = R_;

    return();
}

func split_128{range_check_ptr}(a: felt) -> (low: felt, high: felt) {
    alloc_locals;
    local low: felt;
    local high: felt;

    %{
        ids.low = ids.a & ((1<<128) - 1)
        ids.high = ids.a >> 128
    %}
    return (low, high);
}


func verify_schnorr_signature_bn254{output_ptr : felt*, poseidon_ptr: PoseidonBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*}(
    P_s_x_low: felt,
    P_s_x_high: felt,
    P_s_y_low: felt,
    P_s_y_high: felt,
    P_u_x_low: felt,
    P_u_x_high: felt,
    P_u_y_low: felt,
    P_u_y_high: felt,
    s: felt,
    R_x_low: felt,
    R_x_high: felt,
    R_y_low: felt,
    R_y_high: felt,
    i: felt,
    m_low: felt,
    m_high: felt
){
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();

    let Gx: BigInt3 = BigInt3(60193888514187762220203334, P1, P2);
    local G: G1PointFull = G1PointFull(x=Gx, y=BigInt3(1, 0, 0));

    // let P_s_x_uint: Uint256 = Uint256(P_s_x_low, P_s_x_high);
    // let P_s_x_bigint: BigInt3 = uint256_to_bigint(P_s_x_uint);

    // let P_s_y_uint: Uint256 = Uint256(P_s_y_low, P_s_y_high);
    // let P_s_y_bigint: BigInt3 = uint256_to_bigint(P_s_y_uint);

    // local P_s: G1PointFull = G1PointFull(x=P_s_x_bigint, y=P_s_y_bigint);

    // let P_u_x_uint: Uint256 = Uint256(P_u_x_low, P_u_x_high);
    // let P_u_x_bigint: BigInt3 = uint256_to_bigint(P_u_x_uint);

    // let P_u_y_uint: Uint256 = Uint256(P_u_y_low, P_u_y_high);
    // let P_u_y_bigint: BigInt3 = uint256_to_bigint(P_u_y_uint);

    // local P_u: G1PointFull = G1PointFull(x=P_u_x_bigint, y=P_u_y_bigint);

    // let s_x_uint: Uint256 = Uint256(s_x_low, s_x_high);
    // let s_x_bigint: BigInt3 = uint256_to_bigint(s_x_uint);

    // let s_y_uint: Uint256 = Uint256(s_y_low, s_y_high);
    // let s_y_bigint: BigInt3 = uint256_to_bigint(s_y_uint);

    // local s: G1PointFull = G1PointFull(x=s_x_bigint, y=s_y_bigint);

    // let R_x_uint: Uint256 = Uint256(R_x_low, R_x_high);
    // let R_x_bigint: BigInt3 = uint256_to_bigint(R_x_uint);

    // let R_y_uint: Uint256 = Uint256(R_y_low, R_y_high);
    // let R_y_bigint: BigInt3 = uint256_to_bigint(R_y_uint);

    // local R: G1PointFull = G1PointFull(x=R_x_bigint, y=R_y_bigint);

    // let (test) = poseidon_hash{poseidon_ptr=poseidon_ptr}(P_u_x, P_u_y);
    // serialize_word(test);

    // serialize_word(P_u_x);
    // serialize_word(P_u_y);
    // serialize_word(P_s_x);
    // serialize_word(P_s_y);

    serialize_word(P_u_x_low);
    serialize_word(P_u_x_high);
    serialize_word(P_u_y_low);
    serialize_word(P_u_y_high);
    serialize_word(P_s_x_low);
    serialize_word(P_s_x_high);
    serialize_word(P_s_y_low);
    serialize_word(P_s_y_high);

    let (l_inputs: felt*) = alloc();
    assert[l_inputs]     = P_u_x_low;
    assert[l_inputs + 1] = P_u_x_high;
    assert[l_inputs + 2] = P_u_y_low;
    assert[l_inputs + 3] = P_u_y_high;
    assert[l_inputs + 4] = P_s_x_low;
    assert[l_inputs + 5] = P_s_x_high;
    assert[l_inputs + 6] = P_s_y_low;
    assert[l_inputs + 7] = P_s_y_high;

    let (l) = poseidon_hash_many{poseidon_ptr=poseidon_ptr}(8, l_inputs);
    serialize_word(l);
    let (l_low, l_high) = split_128(l);


    let (w_u_inputs: felt*) = alloc();
    assert[w_u_inputs]     = l_low;
    assert[w_u_inputs + 1] = l_high;
    assert[w_u_inputs + 2] = P_u_x_low;
    assert[w_u_inputs + 3] = P_u_x_high;
    assert[w_u_inputs + 4] = P_u_y_low;
    assert[w_u_inputs + 5] = P_u_y_high;

    let (w_u) = poseidon_hash_many{poseidon_ptr=poseidon_ptr}(6, w_u_inputs);
    serialize_word(w_u);
    let (w_u_low, w_u_high) = split_128(w_u);
    serialize_word(w_u_low);
    serialize_word(w_u_high);
    let w_u_uint: Uint256 = Uint256(w_u_low, w_u_high);
    let w_u_bigint: BigInt3 = uint256_to_bigint(w_u_uint);

    let (w_s_inputs: felt*) = alloc();
    assert[w_s_inputs]     = l_low;
    assert[w_s_inputs + 1] = l_high;
    assert[w_s_inputs + 2] = P_s_x_low;
    assert[w_s_inputs + 3] = P_s_x_high;
    assert[w_s_inputs + 4] = P_s_y_low;
    assert[w_s_inputs + 5] = P_s_y_high;

    let (w_s) = poseidon_hash_many{poseidon_ptr=poseidon_ptr}(6, w_s_inputs);
    serialize_word(w_s);
    let (w_s_low, w_s_high) = split_128(w_s);
    serialize_word(w_s_low);
    serialize_word(w_s_high);
    let w_s_uint: Uint256 = Uint256(w_s_low, w_s_high);
    let w_s_bigint: BigInt3 = uint256_to_bigint(w_s_uint);

    let P_u_x_uint: Uint256 = Uint256(P_u_x_low, P_u_x_high);
    let P_u_x_bigint: BigInt3 = uint256_to_bigint(P_u_x_uint);

    let P_u_y_uint: Uint256 = Uint256(P_u_y_low, P_u_y_high);
    let P_u_y_bigint: BigInt3 = uint256_to_bigint(P_u_y_uint);

    local P_u: G1PointFull = G1PointFull(x=P_u_x_bigint, y=P_u_y_bigint);

    let P_s_x_uint: Uint256 = Uint256(P_s_x_low, P_s_x_high);
    let P_s_x_bigint: BigInt3 = uint256_to_bigint(P_s_x_uint);

    let P_s_y_uint: Uint256 = Uint256(P_s_y_low, P_s_y_high);
    let P_s_y_bigint: BigInt3 = uint256_to_bigint(P_s_y_uint);

    local P_s: G1PointFull = G1PointFull(x=P_s_x_bigint, y=P_s_y_bigint);

    let (w_P_u) = g1.scalar_mul(new G1Point(&P_u.x, &P_u.y), w_u_bigint);
    let (w_P_s) = g1.scalar_mul(new G1Point(&P_s.x, &P_s.y), w_s_bigint);
    let (X) = g1.add(w_P_u, w_P_s);


    let X_x_bigint3: BigInt3 = BigInt3(X.x.d0, X.x.d1, X.x.d2);
    let X_x_uint256: Uint256 = bigint_to_uint256(X_x_bigint3);
    let X_y_bigint3: BigInt3 = BigInt3(X.y.d0, X.y.d1, X.y.d2);
    let X_y_uint256: Uint256 = bigint_to_uint256(X_y_bigint3);

    let R_x_uint: Uint256 = Uint256(R_x_low, R_x_high);
    let R_x_bigint: BigInt3 = uint256_to_bigint(R_x_uint);

    let R_y_uint: Uint256 = Uint256(R_y_low, R_y_high);
    let R_y_bigint: BigInt3 = uint256_to_bigint(R_y_uint);

    local R: G1PointFull = G1PointFull(x=R_x_bigint, y=R_y_bigint);

    let (e_inputs: felt*) = alloc();
    assert[e_inputs]     = R_x_low;
    assert[e_inputs + 1] = R_x_high;
    assert[e_inputs + 2] = R_y_low;
    assert[e_inputs + 3] = R_y_high;
    assert[e_inputs + 4] = X_x_uint256.low;
    assert[e_inputs + 5] = X_x_uint256.high;
    assert[e_inputs + 6] = X_y_uint256.low;
    assert[e_inputs + 7] = X_y_uint256.high;
    assert[e_inputs + 8] = m_low;
    assert[e_inputs + 9] = m_high;
    assert[e_inputs + 10] = i;

    let (e) = poseidon_hash_many{poseidon_ptr=poseidon_ptr}(11, e_inputs);
    serialize_word(e);
    let (e_low, e_high) = split_128(e);
    serialize_word(e_low);
    serialize_word(e_high);

    let e_uint: Uint256 = Uint256(e_low, e_high);
    let e_bigint: BigInt3 = uint256_to_bigint(e_uint);

    let (s_low, s_high) = split_felt(s);
    let s_uint: Uint256 = Uint256(s_low, s_high);
    let s_bigint: BigInt3 = uint256_to_bigint(s_uint);


    // let (_challenge) = poseidon_hash{poseidon_ptr=poseidon_ptr}(mod_alpha_G_x, mod_alpha_G_y);

    // let (chal_low, chal_high) = split_128(_challenge);
    // let chal_uint: Uint256 = Uint256(chal_low, chal_high);
    // let challenge: BigInt3 = uint256_to_bigint(chal_uint);

    // let res_uint: Uint256 = Uint256(response_low, response_high);
    // let res: BigInt3 = uint256_to_bigint(res_uint);

    // let (R) = g1.scalar_mul(new G1Point(&G.x, &G.y), res);
    // let (c_k) = g1.scalar_mul(new G1Point(&public_key.x, &public_key.y), challenge);
    // let (R_) = g1.add(new G1Point(&alpha_G.x, &alpha_G.y), c_k);

    let (left) = g1.scalar_mul(new G1Point(&G.x, &G.y), s_bigint);

    let left_x_bigint: BigInt3 = BigInt3(left.x.d0, left.x.d1, left.x.d2);
    let left_x_uint: Uint256 = bigint_to_uint256(left_x_bigint);
    serialize_word(left_x_uint.low);
    serialize_word(left_x_uint.high);

    let (eX) = g1.scalar_mul(X, e_bigint);
    let (right) = g1.add(new G1Point(&R.x, &R.y), eX);


    // assert left.x.d0 = right.x.d0;
    // assert left.x.d1 = right.x.d1;
    // assert left.x.d2 = right.x.d2;
    // assert left.y.d0 = right.y.d0;
    // assert left.y.d1 = right.y.d1;
    // assert left.y.d2 = right.y.d2;

    return ();
}

    // P_s_x_low: felt,
    // P_s_x_high: felt,
    // P_s_y_low: felt,
    // P_s_y_high: felt,
    // P_u_x_low: felt,
    // P_u_x_high: felt,
    // P_u_y_low: felt,
    // P_u_y_high: felt,
    // s_x_low: felt,
    // s_x_high: felt,
    // s_y_low: felt,
    // s_y_high: felt,
    // R_x_low: felt,
    // R_x_high: felt,
    // R_y_low: felt,
    // R_y_high: felt,