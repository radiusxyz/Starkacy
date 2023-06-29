%builtins output range_check bitwise ec_op poseidon

from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import assert_on_curve, ec_add, ec_double, ec_op
from starkware.cairo.common.cairo_builtins import EcOpBuiltin, BitwiseBuiltin, HashBuiltin, PoseidonBuiltin
from starkware.cairo.common.serialize import serialize_word
from src.math_utils import ec_mul
from src.schnorr import verify_schnorr_signature_bn254
from starkware.cairo.common.hash import hash2

func main{output_ptr: felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*, poseidon_ptr: PoseidonBuiltin*}() {
    alloc_locals;

    local P_s_x_low: felt;
    local P_s_x_high: felt;
    local P_s_y_low: felt;
    local P_s_y_high: felt;
    local P_u_x_low: felt;
    local P_u_x_high: felt;
    local P_u_y_low: felt;
    local P_u_y_high: felt;
    local s: felt;
    local R_x_low: felt;
    local R_x_high: felt;
    local R_y_low: felt;
    local R_y_high: felt;
    local i: felt;
    local m_low: felt;
    local m_high: felt;

    %{
        import sys, os
        cwd = os.getcwd()
        sys.path.append(cwd)

        from src.schnorrpy import SchnorrSignatureBN254
        from starkware.cairo.common.cairo_secp.secp_utils import split

        def to_field_element(val: int, prime: int) -> int:
            """
            Converts val to an integer in the range (-prime/2, prime/2) which is
            equivalent to val modulo prime.
            """
            half_prime = prime // 2
            return ((val + half_prime) % prime) - half_prime
        

        schnorr = SchnorrSignatureBN254()
        (P_s, P_u, s, R, i, m) = schnorr.prove()
        print("Off-chain proof sent")
        schnorr.verify(P_s, P_u ,s, R, i, m)
        print("Off-chain verification done")
        print("Assertting on-chain verification")
        print("If there is no error, on-chain verification is completed")

        FIELD_PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481
        s_felt = to_field_element(s, FIELD_PRIME)
        print('s_felt: ', s_felt)
        print(s_felt & ((1<<128) - 1), s_felt >> 128)

        ids.P_s_x_low = P_s.x & ((1<<128) - 1)
        ids.P_s_x_high = P_s.x >> 128
        ids.P_s_y_low = P_s.y & ((1<<128) - 1)
        ids.P_s_y_high = P_s.y >> 128
        ids.P_u_x_low = P_u.x & ((1<<128) - 1)
        ids.P_u_x_high = P_u.x >> 128
        ids.P_u_y_low = P_u.y & ((1<<128) - 1)
        ids.P_u_y_high = P_u.y >> 128
        ids.s = to_field_element(s, FIELD_PRIME)
        ids.R_x_low = R.x & ((1<<128) - 1)
        ids.R_x_high = R.x >> 128
        ids.R_y_low = R.y & ((1<<128) - 1)
        ids.R_y_high = R.y >> 128
        ids.i = i
        ids.m_low = m & ((1<<128) - 1)
        ids.m_high = m >> 128
    %}

    verify_schnorr_signature_bn254(
        P_s_x_low,
        P_s_x_high,
        P_s_y_low,
        P_s_y_high,
        P_u_x_low,
        P_u_x_high,
        P_u_y_low,
        P_u_y_high,
        s,
        R_x_low,
        R_x_high,
        R_y_low,
        R_y_high,
        i,
        m_low,
        m_high
    );

    return ();
}