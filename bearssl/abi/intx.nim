import
  "."/[csources]

{.used.}

const
  bearIntPath = bearSrcPath & "int/"

{.compile: bearIntPath & "i15_add.c".}
{.compile: bearIntPath & "i15_bitlen.c".}
{.compile: bearIntPath & "i15_decmod.c".}
{.compile: bearIntPath & "i15_decode.c".}
{.compile: bearIntPath & "i15_decred.c".}
{.compile: bearIntPath & "i15_encode.c".}
{.compile: bearIntPath & "i15_fmont.c".}
{.compile: bearIntPath & "i15_iszero.c".}
{.compile: bearIntPath & "i15_moddiv.c".}
{.compile: bearIntPath & "i15_modpow.c".}
{.compile: bearIntPath & "i15_modpow2.c".}
{.compile: bearIntPath & "i15_montmul.c".}
{.compile: bearIntPath & "i15_mulacc.c".}
{.compile: bearIntPath & "i15_muladd.c".}
{.compile: bearIntPath & "i15_ninv15.c".}
{.compile: bearIntPath & "i15_reduce.c".}
{.compile: bearIntPath & "i15_rshift.c".}
{.compile: bearIntPath & "i15_sub.c".}
{.compile: bearIntPath & "i15_tmont.c".}
{.compile: bearIntPath & "i31_add.c".}
{.compile: bearIntPath & "i31_bitlen.c".}
{.compile: bearIntPath & "i31_decmod.c".}
{.compile: bearIntPath & "i31_decode.c".}
{.compile: bearIntPath & "i31_decred.c".}
{.compile: bearIntPath & "i31_encode.c".}
{.compile: bearIntPath & "i31_fmont.c".}
{.compile: bearIntPath & "i31_iszero.c".}
{.compile: bearIntPath & "i31_moddiv.c".}
{.compile: bearIntPath & "i31_modpow.c".}
{.compile: bearIntPath & "i31_modpow2.c".}
{.compile: bearIntPath & "i31_montmul.c".}
{.compile: bearIntPath & "i31_mulacc.c".}
{.compile: bearIntPath & "i31_muladd.c".}
{.compile: bearIntPath & "i31_ninv31.c".}
{.compile: bearIntPath & "i31_reduce.c".}
{.compile: bearIntPath & "i31_rshift.c".}
{.compile: bearIntPath & "i31_sub.c".}
{.compile: bearIntPath & "i31_tmont.c".}
{.compile: bearIntPath & "i32_add.c".}
{.compile: bearIntPath & "i32_bitlen.c".}
{.compile: bearIntPath & "i32_decmod.c".}
{.compile: bearIntPath & "i32_decode.c".}
{.compile: bearIntPath & "i32_decred.c".}
{.compile: bearIntPath & "i32_div32.c".}
{.compile: bearIntPath & "i32_encode.c".}
{.compile: bearIntPath & "i32_fmont.c".}
{.compile: bearIntPath & "i32_iszero.c".}
{.compile: bearIntPath & "i32_modpow.c".}
{.compile: bearIntPath & "i32_montmul.c".}
{.compile: bearIntPath & "i32_mulacc.c".}
{.compile: bearIntPath & "i32_muladd.c".}
{.compile: bearIntPath & "i32_ninv32.c".}
{.compile: bearIntPath & "i32_reduce.c".}
{.compile: bearIntPath & "i32_sub.c".}
{.compile: bearIntPath & "i32_tmont.c".}
{.compile: bearIntPath & "i62_modpow2.c".}
