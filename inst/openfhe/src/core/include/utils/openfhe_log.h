// Diagnostic logging channel for OpenFHE.
//
// Call sites that previously wrote directly to std::cerr / std::cout
// should use OPENFHE_LOG_ERR / OPENFHE_LOG_OUT so the output stream
// can be swapped per embedding without touching every call site.
//
// When OPENFHE_R_BUILD is defined (as it is by the `openfhe` R
// package's inst/build_openfhe.sh), the macros expand to references
// to persistent std::ostream objects — `lbcrypto::r_cerr()` and
// `lbcrypto::r_cout()` — whose underlying streambufs route through
// R's REprintf / Rprintf entry points. The functions are DECLARED
// here but DEFINED in the R package's src/r_streams.cpp, which is
// linked into the final openfhe.so. Compiled OpenFHE static archives
// thus contain NO references to std::cerr / std::cout / std::clog,
// which satisfies R CMD check's "checking compiled code" rule
// (Writing R Extensions §1.1.3.1 step 16).
//
// Returning `std::ostream&` (not a custom wrapper class) means every
// built-in `operator<<` overload — including manipulators like
// `std::endl`, `std::flush`, `std::hex`, etc. — works transparently.
//
// Otherwise — the upstream OpenFHE build without OPENFHE_R_BUILD —
// the macros expand to the ordinary std::cerr / std::cout streams,
// preserving the pre-existing behavior for non-R embeddings.

#ifndef _LBCRYPTO_UTILS_OPENFHE_LOG_H_
#define _LBCRYPTO_UTILS_OPENFHE_LOG_H_

#ifdef OPENFHE_R_BUILD

#include <ostream>

namespace lbcrypto {
std::ostream& r_cerr();
std::ostream& r_cout();
}  // namespace lbcrypto

#define OPENFHE_LOG_ERR (::lbcrypto::r_cerr())
#define OPENFHE_LOG_OUT (::lbcrypto::r_cout())

#else  // OPENFHE_R_BUILD not defined — ordinary upstream build

#include <iostream>

#define OPENFHE_LOG_ERR (::std::cerr)
#define OPENFHE_LOG_OUT (::std::cout)

#endif  // OPENFHE_R_BUILD

#endif  // _LBCRYPTO_UTILS_OPENFHE_LOG_H_
