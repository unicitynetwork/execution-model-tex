# The Unicity Execution Layer

[The Unicity Execution Layer (paper, PDF)](https://github.com/unicitynetwork/execution-model-tex/releases/download/latest/unicity-execution-layer.pdf)

[Presentation (video recording)](https://www.youtube.com/watch?v=Cgfpkc2let8)

EasyCrypt security proofs of the main theorems:
- [Security against Blocking](unicity_blocking.ec)
- [Security against Double-Spending](unicity_double_spend.ec)

[Unicity: Predicates and Atomic Swaps (follow-up paper, PDf)](https://github.com/unicitynetwork/unicity-predicates-tex/releases/download/latest/unicity-predicates.pdf)

## Abstract

>  This paper introduces the Unicity Execution Layer, a modular component of the Unicity framework enabling secure off-chain transactions while maintaining trustless double-spending prevention. We present a formal security model where token ownership is represented by public keys and transfers require digital signatures. We prove three fundamental security properties: (1) no double-spending---each token state can be spent at most once, (2) no blocking---only the legitimate owner can prevent a token from being spent, and (3) service-side privacy---the Unicity Service cannot link transactions with the same token. The user-side privacy is addressed by introducing generalized multi-public-key signature schemes that allow one secret to generate multiple unlinkable public keys, and an interactive and non-interactive concrete instantiations, enabling private transactions with stable public identity with minimal key management overhead.

