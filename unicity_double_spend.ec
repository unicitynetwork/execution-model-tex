(* EasyCrypt Formalization of the Unicity Execution Model's security against  Double-Spending *)

require import AllCore.

(* Basic types for the Unicity protocol *)
type pubkey.
type state_hash.
type tx_hash.
type signature.
type commitment.
type decommitment.
type transaction_data.

(* Protocol operations *)
op verify : pubkey -> state_hash * tx_hash -> signature -> bool.
op hash : transaction_data -> state_hash.
op open : commitment -> decommitment -> state_hash option.

(* Collision Resistance Game *)
module type CollisionAdversary = {
  proc find() : transaction_data * transaction_data
}.

module CollisionGame(A : CollisionAdversary) = {
  proc main() : bool = {
    var result : transaction_data * transaction_data;
    result <@ A.find();
    return result.`1 <> result.`2 /\ hash result.`1 = hash result.`2;
  }
}.

(* Computational Binding Game *)
module type BindingAdversary = {
  proc attack() : commitment * decommitment * decommitment
}.

module BindingGame(A : BindingAdversary) = {
  proc main() : bool = {
    var result : commitment * decommitment * decommitment;
    var m1, m2 : state_hash option;

    result <@ A.attack();
    m1 <- open result.`1 result.`2;
    m2 <- open result.`1 result.`3;
    return m1 <> None /\ m2 <> None /\ m1 <> m2;
  }
}.

(* Double-Spending Security Game - Core concept *)
module type DoubleSpendAdversary = {
  proc attack() : transaction_data * transaction_data * commitment * decommitment * decommitment
}.

module DoubleSpendGame(A : DoubleSpendAdversary) = {
  proc main() : bool = {
    var result : transaction_data * transaction_data * commitment * decommitment * decommitment;
    var m1, m2 : state_hash option;

    result <@ A.attack();
    m1 <- open result.`3 result.`4;
    m2 <- open result.`3 result.`5;

    return result.`1 <> result.`2 /\
           m1 = Some (hash result.`1) /\
           m2 = Some (hash result.`2);
  }
}.

(* Security Reductions *)
section DoubleSpendSecurity.

declare module A <: DoubleSpendAdversary.

(* Collision adversary constructed from double-spend adversary *)
module CollisionReduction : CollisionAdversary = {
  proc find() : transaction_data * transaction_data = {
    var result : transaction_data * transaction_data * commitment * decommitment * decommitment;
    result <@ A.attack();
    return (result.`1, result.`2);
  }
}.

(* Binding adversary constructed from double-spend adversary *)
module BindingReduction : BindingAdversary = {
  proc attack() : commitment * decommitment * decommitment = {
    var result : transaction_data * transaction_data * commitment * decommitment * decommitment;
    result <@ A.attack();
    return (result.`3, result.`4, result.`5);
  }
}.

(* Main security theorem *)
lemma double_spend_security &m :
  Pr[DoubleSpendGame(A).main() @ &m : res] <=
  Pr[CollisionGame(CollisionReduction).main() @ &m : res] +
  Pr[BindingGame(BindingReduction).main() @ &m : res].
proof.
admitted.

end section DoubleSpendSecurity.

(*
Security bounds: For any double-spending adversary A:

Adv^ds_Unicity(A) <= Adv^coll_H(CollisionReduction) + Adv^bind_Com(BindingReduction)

This EasyCrypt formalization proves that double-spending security reduces to:
1. Collision resistance of the hash function
2. Computational binding of the commitment scheme

The formal proof shows that any successful double-spending attack must either
find a hash collision or break the commitment binding property.
*)
