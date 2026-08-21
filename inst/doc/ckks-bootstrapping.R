## ----setup, include = FALSE---------------------------------------------------
# Cap OpenMP to CRAN's two-core policy (see ?openfhe.R::set_num_threads).
library(openfhe.R)
openfhe.R::set_num_threads(2L)
knitr::opts_chunk$set(
  collapse = TRUE,
  comment = "#>"
)

## ----depth-budget-------------------------------------------------------------
library(openfhe.R)

cc_shallow <- fhe_context("CKKS",
  multiplicative_depth = 3L,
  scaling_mod_size     = 50L,
  batch_size           = 8L
)
kp_shallow <- key_gen(cc_shallow, eval_mult = TRUE)

x <- c(0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5)
pt <- make_ckks_packed_plaintext(cc_shallow, x)
ct <- encrypt(kp_shallow@public, pt, cc = cc_shallow)

## Three multiplications in sequence — right at the depth
## budget. This succeeds.
ct_a <- ct * ct           # level 1
ct_b <- ct_a * ct         # level 2
ct_c <- ct_b * ct         # level 3
res <- decrypt(ct_c, kp_shallow@secret, cc = cc_shallow)
set_length(res, 8L)
round(get_real_packed_value(res)[1:3], 5)
## ~ c(0.5^4, 0.5^4, 0.5^4) = c(0.0625, 0.0625, 0.0625)

## ----noninteractive-setup-----------------------------------------------------
## Choose the bootstrap level budget. The two integers are
## the encoding and decoding budgets; (3, 3) is a reasonable
## middle ground. Larger values give faster bootstrap at the
## cost of deeper required chain.
level_budget   <- c(3L, 3L)
secret_key_dist <- SecretKeyDist$UNIFORM_TERNARY

boot_depth <- get_bootstrap_depth(level_budget, secret_key_dist)
boot_depth

## User compute budget after a single bootstrap — how many
## multiplications we want to do between refreshes.
user_depth <- 2L

total_depth <- boot_depth + user_depth
total_depth

## ----noninteractive-context---------------------------------------------------
cc <- fhe_context("CKKS",
  multiplicative_depth = total_depth,
  scaling_mod_size     = 59L,
  first_mod_size       = 60L,
  ring_dim             = 4096L,
  security_level       = SecurityLevel$HEStd_NotSet,
  scaling_technique    = ScalingTechnique$FLEXIBLEAUTO,
  features             = c(Feature$ADVANCEDSHE, Feature$FHE)
)
kp <- key_gen(cc, eval_mult = TRUE)

## ----noninteractive-keygen----------------------------------------------------
## ring_dim / 2 is the number of CKKS slots. Query it off
## the context rather than hard-coding.
ring_dim  <- ring_dimension(cc)
num_slots <- as.integer(ring_dim / 2)

eval_bootstrap_setup(cc, level_budget = level_budget)
eval_bootstrap_key_gen(cc, kp@secret, num_slots)

## ----noninteractive-run-------------------------------------------------------
y <- c(0.25, 0.5, 0.75, 1.0)
pt_y <- make_ckks_packed_plaintext(cc, y)
ct_y <- encrypt(kp@public, pt_y, cc = cc)

## Burn a couple of levels to simulate "the user circuit has
## run and now we need to refresh".
ct_y <- ct_y * ct_y     # y^2
## At this point ct_y sits at a lower level than it started.

## One bootstrap call refreshes the ciphertext. Default
## num_iterations = 1L is the standard case.
ct_refreshed <- eval_bootstrap(ct_y)

## Decrypt the refreshed ciphertext and confirm it holds
## the same value as y^2 did.
res_refresh <- decrypt(ct_refreshed, kp@secret, cc = cc)
set_length(res_refresh, 4L)
round(get_real_packed_value(res_refresh)[1:4], 4)
## ~ c(0.0625, 0.25, 0.5625, 1.0) = y^2

## ----iterative-bootstrap, eval = FALSE----------------------------------------
# ## Same cc, same keys — just more iterations per call.
# ct_refreshed_2 <- eval_bootstrap(ct_y, num_iterations = 2L)

## ----mp-bootstrap-setup-------------------------------------------------------
cc_mp <- fhe_context("CKKS",
  multiplicative_depth = 6L,
  scaling_mod_size     = 50L,
  first_mod_size       = 60L,
  ring_dim             = 4096L,
  security_level       = SecurityLevel$HEStd_NotSet,
  batch_size           = 8L,
  features             = c(Feature$ADVANCEDSHE, Feature$FHE,
                           Feature$MULTIPARTY)
)
kp1 <- key_gen(cc_mp, eval_mult = TRUE)
kp2 <- multiparty_key_gen(cc_mp, kp1@public)

## ----mp-bootstrap-decrypt-----------------------------------------------------
z <- c(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8)
pt_z <- make_ckks_packed_plaintext(cc_mp, z)
ct_z <- encrypt(kp2@public, pt_z, cc = cc_mp)

## Step 1: scale adjustment. Prepares the ciphertext for
## the interactive refresh protocol.
ct_z_adjusted <- int_mp_boot_adjust_scale(ct_z)

## Step 2: generate the common random element. Can be
## derived from either the lead party's public key or from
## a reference ciphertext — the two overloads produce
## equivalent output.
a <- int_mp_boot_random_element_gen(cc_mp, kp1@public)

## Step 3: each party computes their masked-decryption
## shares pair. Each party's output is a list of two
## Ciphertexts.
shares1 <- int_mp_boot_decrypt(kp1@secret, ct_z_adjusted, a)
shares2 <- int_mp_boot_decrypt(kp2@secret, ct_z_adjusted, a)

## ----mp-bootstrap-finalize----------------------------------------------------
## Aggregate both parties' shares pairs.
aggregated <- int_mp_boot_add(cc_mp, list(shares1, shares2))

## Final re-encryption step.
ct_refreshed_mp <- int_mp_boot_encrypt(kp1@public, aggregated,
                                       a, ct_z_adjusted)

