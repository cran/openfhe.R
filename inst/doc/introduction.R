## ----setup, include = FALSE---------------------------------------------------
library(openfhe.R)
knitr::opts_chunk$set(
  collapse = TRUE,
  comment = "#>"
)

## ----bfv-context--------------------------------------------------------------
library(openfhe.R)

cc <- fhe_context("BFV",
  plaintext_modulus    = 65537,
  multiplicative_depth = 2
)
keys <- key_gen(cc, eval_mult = TRUE)

## ----bfv-encrypt--------------------------------------------------------------
x <- c(1, 2, 3, 4, 5, 6, 7, 8)
y <- c(10, 20, 30, 40, 50, 60, 70, 80)

ct_x <- encrypt(keys@public, make_packed_plaintext(cc, x), cc = cc)
ct_y <- encrypt(keys@public, make_packed_plaintext(cc, y), cc = cc)

## ----bfv-compute--------------------------------------------------------------
ct_sum  <- ct_x + ct_y
ct_prod <- ct_x * ct_y

## ----bfv-decrypt--------------------------------------------------------------
result_sum  <- decrypt(ct_sum,  keys@secret, cc = cc)
result_prod <- decrypt(ct_prod, keys@secret, cc = cc)
set_length(result_sum,  8)
set_length(result_prod, 8)

sum_vec  <- get_packed_value(result_sum)
prod_vec <- get_packed_value(result_prod)
sum_vec
prod_vec

## ----ckks-context-------------------------------------------------------------
cc <- fhe_context("CKKS",
  multiplicative_depth = 1,
  scaling_mod_size     = 50,
  batch_size           = 8
)
keys <- key_gen(cc, eval_mult = TRUE)

## ----ckks-encrypt-------------------------------------------------------------
x  <- c(0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0)
ct <- encrypt(keys@public, make_ckks_packed_plaintext(cc, x), cc = cc)

ct_doubled <- ct + ct
ct_squared <- ct * ct
ct_scaled  <- ct * 4.0

## ----ckks-decrypt-------------------------------------------------------------
result <- decrypt(ct_doubled, keys@secret, cc = cc)
set_length(result, 8)
doubled_vec <- get_real_packed_value(result)
doubled_vec

## ----ckks-error---------------------------------------------------------------
max_err <- max(abs(doubled_vec - 2 * x))
max_err

## ----binfhe-context-----------------------------------------------------------
ctx <- bin_fhe_context(BinFHEParamSet$STD128, BinFHEMethod$GINX)
sk  <- bin_key_gen(ctx)
bin_bt_key_gen(ctx, sk)

## ----binfhe-gates-------------------------------------------------------------
ct_a <- bin_encrypt(ctx, sk, 1L)
ct_b <- bin_encrypt(ctx, sk, 0L)

ct_and <- eval_bin_gate(ctx, BinGate$AND, ct_a, ct_b)
ct_or  <- eval_bin_gate(ctx, BinGate$OR,
                        bin_encrypt(ctx, sk, 1L),
                        bin_encrypt(ctx, sk, 0L))

and_bit <- bin_decrypt(ctx, sk, ct_and)
or_bit  <- bin_decrypt(ctx, sk, ct_or)
and_bit
or_bit

## ----serialize----------------------------------------------------------------
tdir <- tempdir()

fhe_serialize(cc, file.path(tdir, "context.bin"))
fhe_serialize(keys@public, file.path(tdir, "pubkey.bin"))
fhe_serialize(ct, file.path(tdir, "ciphertext.bin"))
serialize_eval_keys(file.path(tdir, "mult_keys.bin"), "mult")

cc2 <- fhe_deserialize(file.path(tdir, "context.bin"),    "CryptoContext")
ct2 <- fhe_deserialize(file.path(tdir, "ciphertext.bin"), "Ciphertext")

## ----threshold-setup----------------------------------------------------------
cc_mp <- fhe_context("BFV",
  plaintext_modulus    = 65537,
  multiplicative_depth = 2,
  features             = c(Feature$MULTIPARTY)
)

kp_a <- key_gen(cc_mp)
kp_b <- multiparty_key_gen(cc_mp, kp_a@public)

ct_mp <- encrypt(kp_b@public,
                 make_packed_plaintext(cc_mp, 1:8),
                 cc = cc_mp)

## ----threshold-decrypt--------------------------------------------------------
partial_a <- multiparty_decrypt_lead(cc_mp, kp_a@secret, ct_mp)
partial_b <- multiparty_decrypt_main(cc_mp, kp_b@secret, ct_mp)
result_mp <- multiparty_decrypt_fusion(cc_mp, partial_a, partial_b)
set_length(result_mp, 8)
mp_vec <- get_packed_value(result_mp)
mp_vec

