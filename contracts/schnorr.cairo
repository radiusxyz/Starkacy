%lang starknet

from starkware.cairo.common.cairo_keccak.keccak import keccak_uint256s, keccak_felts, finalize_keccak
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import assert_on_curve, ec_add, ec_double, ec_op
from starkware.cairo.common.cairo_builtins import EcOpBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.uint256 import Uint256, uint256_le, uint256_unsigned_div_rem
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import split_felt

const BASE_POINT_X = 874739451078007766457464989774322083649278607533249481151382481072868806602;
const BASE_POINT_Y = 152666792071518830868575557812948353041420400780739481342941381225525861407;
const BASE_BLINDING_POINT_X = 1644404348220522245795652770711644747389835183387584438047505930708711545294;
const BASE_BLINDING_POINT_Y = 3418409665108082357574218324957319851728951500117497918120788963183493908527;
const MINUS_1 = 3618502788666131213697322783095070105526743751716087489154079457884512865582;

func ec_mul{ec_op_ptr: EcOpBuiltin*}(p: EcPoint, m: felt) -> (product: EcPoint) {
    alloc_locals;
    local id_point: EcPoint = EcPoint(0, 0);
    let (r: EcPoint) = ec_op(id_point, m, p);
    return (product=r);
}

func felt_to_uint256{range_check_ptr}(x : felt) -> (x_ : Uint256){
    alloc_locals;
    let split = split_felt(x);
    local res : Uint256 = Uint256(low = split.low, high = split.high);
    return (x_ = res);
}

func uint256_to_felt(x : Uint256) -> (x_ : felt){
    alloc_locals;
    local res = x.low + x.high * 2 ** 128;
    return (x_ = res);
}

func mul_mod_Q{range_check_ptr}(x : felt, y : felt) -> (res : felt) {
    alloc_locals;
    local inter = x * y;
    let (inter_256) = felt_to_uint256(inter);
    
    local Q : Uint256 = Uint256(low = 243918903305429252644362009180409056559, high = 10633823966279327296825105735305134079);
    let (_, r) = uint256_unsigned_div_rem(a = inter_256, div = Q);
    let (r_felt) = uint256_to_felt(r);
    
    return (res = r_felt);
}

func uint256_to_address_felt(x : Uint256) -> (address : felt){
    return (address = x.low + x.high * 2 ** 128);
}

@external
func verify_schnorr_signature{pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*}(alpha_G_x: felt, alpha_G_y: felt, response : felt, public_key_x : felt, public_key_y: felt){
    alloc_locals;

    local alpha_G: EcPoint = EcPoint(alpha_G_x, alpha_G_y);
    assert_on_curve(alpha_G);

    local G: EcPoint = EcPoint(BASE_POINT_X, BASE_POINT_Y);
    assert_on_curve(G);

    let (_challenge) = hash2{hash_ptr=pedersen_ptr}(alpha_G.x, alpha_G.y);
    
    local public_key: EcPoint = EcPoint(public_key_x, public_key_y);

    let (R) = ec_mul(G, response);
    let (c_k) = ec_mul(public_key, _challenge);
    let (R_) = ec_add(alpha_G, c_k);

    assert R = R_;

    return();
}