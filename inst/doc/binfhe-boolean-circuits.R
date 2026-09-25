## ----setup, include = FALSE---------------------------------------------------
library(openfhe.R)
knitr::opts_chunk$set(
  collapse = TRUE,
  comment = "#>"
)

## ----setup-toy----------------------------------------------------------------
library(openfhe.R)

## TOY paramset — fast but zero security. For demos only.
ctx <- bin_fhe_context(BinFHEParamSet$TOY, BinFHEMethod$GINX)

## The secret key generates bootstrap keys that every gate
## will use internally.
sk <- bin_key_gen(ctx)
bin_bt_key_gen(ctx, sk)

## ----binary-gates-------------------------------------------------------------
ct0 <- bin_encrypt(ctx, sk, 0L)
ct1 <- bin_encrypt(ctx, sk, 1L)

truth <- function(gate_name, gate, ct_a, ct_b) {
  r <- eval_bin_gate(ctx, gate, ct_a, ct_b)
  bin_decrypt(ctx, sk, r)
}

## Full truth table for AND / OR / XOR.
grid <- expand.grid(a = c(0L, 1L), b = c(0L, 1L))
grid$AND <- mapply(function(a, b) truth("AND", BinGate$AND,
                                         bin_encrypt(ctx, sk, a),
                                         bin_encrypt(ctx, sk, b)),
                    grid$a, grid$b)
grid$OR  <- mapply(function(a, b) truth("OR", BinGate$OR,
                                         bin_encrypt(ctx, sk, a),
                                         bin_encrypt(ctx, sk, b)),
                    grid$a, grid$b)
grid$XOR <- mapply(function(a, b) truth("XOR", BinGate$XOR,
                                         bin_encrypt(ctx, sk, a),
                                         bin_encrypt(ctx, sk, b)),
                    grid$a, grid$b)
grid

## ----not----------------------------------------------------------------------
bin_decrypt(ctx, sk, eval_not(ctx, ct0))
bin_decrypt(ctx, sk, eval_not(ctx, ct1))

## ----multi-input-setup--------------------------------------------------------
ctx3 <- bin_fhe_context(BinFHEParamSet$STD128_3)
sk3 <- bin_key_gen(ctx3)
bin_bt_key_gen(ctx3, sk3)

p3 <- 6L
encrypt_bit_3 <- function(b) {
  bin_encrypt(ctx3, sk3, as.integer(b),
              output = BinFHEOutput$SMALL_DIM,
              p = p3)
}

## ----and3---------------------------------------------------------------------
## 1 AND 1 AND 0 = 0
cts_110 <- list(encrypt_bit_3(1L),
                encrypt_bit_3(1L),
                encrypt_bit_3(0L))
bin_decrypt(ctx3, sk3,
            eval_bin_gate(ctx3, BinGate$AND3, cts_110),
            p = p3)

## 1 AND 1 AND 1 = 1
cts_111 <- list(encrypt_bit_3(1L),
                encrypt_bit_3(1L),
                encrypt_bit_3(1L))
bin_decrypt(ctx3, sk3,
            eval_bin_gate(ctx3, BinGate$AND3, cts_111),
            p = p3)

## ----majority, eval = FALSE---------------------------------------------------
# ## Majority uses p = 4 (not 2 * num_inputs = 6) per the
# ## upstream boolean-multi-input example's encoding.
# p_maj <- 4L
# encrypt_bit_maj <- function(b) {
#   bin_encrypt(ctx3, sk3, as.integer(b),
#               output = BinFHEOutput$SMALL_DIM,
#               p = p_maj)
# }
# 
# cts <- list(encrypt_bit_maj(1L),
#             encrypt_bit_maj(1L),
#             encrypt_bit_maj(0L))
# bin_decrypt(ctx3, sk3,
#             eval_bin_gate(ctx3, BinGate$MAJORITY, cts),
#             p = p_maj)
# ## 1 (majority of two 1s and one 0)

## ----arb-func-----------------------------------------------------------------
## Build an arb-func context. arb_func = TRUE picks a wider
## paramset; log_q and n control the LARGE_DIM modulus and
## dimension of the functional-bootstrap path.
ctx_f <- bin_fhe_context(BinFHEParamSet$TOY,
                          arb_func = TRUE)
sk_f <- bin_key_gen(ctx_f)
bin_bt_key_gen(ctx_f, sk_f)

p <- get_max_plaintext_space(ctx_f)

## Example function: squared value mod p. The LUT maps
## input i in [0, p) to f(i) = i^2 mod p.
f_square <- function(x, plaintext_modulus) {
  (x * x) %% plaintext_modulus
}
lut <- generate_lut_via_function(f_square, p)

## Encrypt a value in the LARGE_DIM / functional-bootstrap
## path and evaluate.
ct_input <- bin_encrypt(ctx_f, sk_f, 3L,
                        output = BinFHEOutput$LARGE_DIM,
                        p = p)
ct_out <- eval_func(ctx_f, ct_input, lut)
bin_decrypt(ctx_f, sk_f, ct_out, p = p)
## 9 (if p > 9, otherwise 9 mod p)

## ----sign-setup---------------------------------------------------------------
log_q <- 17L
ctx_s <- bin_fhe_context(
  paramset           = BinFHEParamSet$STD128,
  method             = BinFHEMethod$GINX,
  arb_func           = FALSE,
  log_q              = log_q,
  n                  = 0L,
  time_optimization  = FALSE
)
sk_s <- bin_key_gen(ctx_s)
bin_bt_key_gen(ctx_s, sk_s)

Q <- bitwShiftL(1L, log_q)                           # 131072
q <- 4096
factor <- bitwShiftL(1L, log_q - as.integer(log2(q))) # 32
p_s <- get_max_plaintext_space(ctx_s) * factor

## ----sign---------------------------------------------------------------------
center <- p_s %/% 2
for (i in 0:7) {
  msg <- center + i - 3
  ct  <- bin_encrypt(ctx_s, sk_s, msg,
                     output = BinFHEOutput$LARGE_DIM,
                     p = p_s, mod = Q)
  ct_sign <- eval_sign(ctx_s, ct)
  ## Decrypt with p = 2 (sign bit is a single bit).
  result <- bin_decrypt(ctx_s, sk_s, ct_sign, p = 2L)
  cat(sprintf("msg = center%+d => sign bit %d\n", i - 3, result))
}

## ----floor--------------------------------------------------------------------
ct_five <- bin_encrypt(ctx_f, sk_f, 5L,
                       output = BinFHEOutput$LARGE_DIM,
                       p = p)
ct_floor <- eval_floor(ctx_f, ct_five, roundbits = 2L)
class(ct_floor)
## Returns an LWECiphertext holding floor(5 / 2^2) = 1 in
## the rounded encoding.

