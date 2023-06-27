from starkware.cairo.common.cairo_keccak.keccak import keccak_uint256s, keccak_felts, finalize_keccak
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import assert_on_curve, ec_add, ec_double, ec_op
from starkware.cairo.common.cairo_builtins import EcOpBuiltin
from src.math_utils import ec_mul, felt_to_uint256, uint256_to_felt
from src.constants import BASE_POINT_X, BASE_POINT_Y
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_unsigned_div_rem, split_64
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.registers import get_fp_and_pc

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


func verify_schnorr_signature_bn254{output_ptr : felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*}(
    alpha_G_x_low : felt, 
    alpha_G_x_high : felt, 
    alpha_G_y_low: felt, 
    alpha_G_y_high: felt, 
    mod_alpha_G_x : felt, 
    mod_alpha_G_y : felt, 
    response_low : felt, 
    response_high : felt, 
    public_key_x_low: felt, 
    public_key_x_high: felt, 
    public_key_y_low: felt,
    public_key_y_high: felt
){
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();

    let Gx: BigInt3 = BigInt3(60193888514187762220203334, P1, P2);
    local G: G1PointFull = G1PointFull(x=Gx, y=BigInt3(1, 0, 0));

    let a_x_uint: Uint256 = Uint256(alpha_G_x_low, alpha_G_x_high);
    let a_x_bigint: BigInt3 = uint256_to_bigint(a_x_uint);

    let a_y_uint: Uint256 = Uint256(alpha_G_y_low, alpha_G_y_high);
    let a_y_bigint: BigInt3 = uint256_to_bigint(a_y_uint);

    local alpha_G: G1PointFull = G1PointFull(x=a_x_bigint, y=a_y_bigint);

    let pub_x_uint: Uint256 = Uint256(public_key_x_low, public_key_x_high);
    let pub_x_bigint: BigInt3 = uint256_to_bigint(pub_x_uint);

    let pub_y_uint: Uint256 = Uint256(public_key_y_low, public_key_y_high);
    let pub_y_bigint: BigInt3 = uint256_to_bigint(pub_y_uint);

    local public_key: G1PointFull = G1PointFull(x=pub_x_bigint, y=pub_y_bigint);

    let (_challenge) = hash2{hash_ptr=pedersen_ptr}(mod_alpha_G_x, mod_alpha_G_y);

    let (chal_low, chal_high) = split_128(_challenge);
    let chal_uint: Uint256 = Uint256(chal_low, chal_high);
    let challenge: BigInt3 = uint256_to_bigint(chal_uint);

    let res_uint: Uint256 = Uint256(response_low, response_high);
    let res: BigInt3 = uint256_to_bigint(res_uint);

    let (R) = g1.scalar_mul(new G1Point(&G.x, &G.y), res);
    let (c_k) = g1.scalar_mul(new G1Point(&public_key.x, &public_key.y), challenge);
    let (R_) = g1.add(new G1Point(&alpha_G.x, &alpha_G.y), c_k);

    assert R_.x.d0 = R.x.d0;
    assert R_.x.d1 = R.x.d1;
    assert R_.x.d2 = R.x.d2;
    assert R_.y.d0 = R.y.d0;
    assert R_.y.d1 = R.y.d1;
    assert R_.y.d2 = R.y.d2;

    return ();
}