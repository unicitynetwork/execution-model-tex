(* ==================================================================== *)
(* EasyCrypt Formalization: Unicity Security against Double-Spending    *)
(* ==================================================================== *)

require import AllCore.

(* --- Basic Types --- *)
type pubkey.
type state_hash.
type tx_hash.
type signature.
type commitment.
type decommitment.
type transaction_data.

(* --- Protocol Operations --- *)
op verify : pubkey -> state_hash * tx_hash -> signature -> bool.
op hash : transaction_data -> state_hash.
op open : commitment -> decommitment -> state_hash option.

(* ==================================================================== *)
(* 1. Pure Mathematical Logic                                           *)
(* ==================================================================== *)

op is_collision (t1 t2 : transaction_data) : bool =
  t1 <> t2 /\ hash t1 = hash t2.

op is_binding_break (m1 m2 : state_hash option) : bool =
  m1 <> None /\ m2 <> None /\ m1 <> m2.

op is_double_spend (t1 t2 : transaction_data) (m1 m2 : state_hash option) : bool =
  t1 <> t2 /\ m1 = Some (hash t1) /\ m2 = Some (hash t2).

(* Pure lemma: A double spend mathematically guarantees a broken primitive *)
lemma ds_implies_coll_or_bind t1 t2 m1 m2 :
  is_double_spend t1 t2 m1 m2 =>
  is_collision t1 t2 \/ is_binding_break m1 m2.
proof. smt(). qed.

(* ==================================================================== *)
(* 2. Cryptographic Games                                               *)
(* ==================================================================== *)

module type CollisionAdversary = {
  proc find() : transaction_data * transaction_data
}.

module CollisionGame(A : CollisionAdversary) = {
  proc main() : bool = {
    var result : transaction_data * transaction_data;
    result <@ A.find();
    return is_collision result.`1 result.`2;
  }
}.

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
    return is_binding_break m1 m2;
  }
}.

module type DoubleSpendAdversary = {
  proc attack() : transaction_data * transaction_data * commitment * decommitment * decommitment
}.

module DoubleSpendGame(A : DoubleSpendAdversary) = {
  var result : transaction_data * transaction_data * commitment * decommitment * decommitment
  var m1, m2 : state_hash option

  proc main() : bool = {
    result <@ A.attack();
    m1 <- open result.`3 result.`4;
    m2 <- open result.`3 result.`5;
    return is_double_spend result.`1 result.`2 m1 m2;
  }
}.

(* ==================================================================== *)
(* 3. Security Reductions & Main Theorem                                *)
(* ==================================================================== *)
section DoubleSpendSecurity.

declare module A <: DoubleSpendAdversary.

module CollisionReduction(B : DoubleSpendAdversary) : CollisionAdversary = {
  proc find() : transaction_data * transaction_data = {
    var result : transaction_data * transaction_data * commitment * decommitment * decommitment;
    result <@ B.attack();
    return (result.`1, result.`2);
  }
}.

module BindingReduction(B : DoubleSpendAdversary) : BindingAdversary = {
  proc attack() : commitment * decommitment * decommitment = {
    var result : transaction_data * transaction_data * commitment * decommitment * decommitment;
    result <@ B.attack();
    return (result.`3, result.`4, result.`5);
  }
}.

(* pRHL reflexivity: running the adversary from identical states yields identical results *)
declare axiom A_attack_coupling :
  equiv[A.attack ~ A.attack : ={glob A} ==> ={glob A, res}].

(* Main Security Theorem *)
lemma double_spend_security &m :
  Pr[DoubleSpendGame(A).main() @ &m : res] <=
  Pr[CollisionGame(CollisionReduction(A)).main() @ &m : res] +
  Pr[BindingGame(BindingReduction(A)).main() @ &m : res].
proof.

(* Step 1: Relate CollisionGame to DoubleSpendGame's collision sub-event *)
have hcoll : Pr[CollisionGame(CollisionReduction(A)).main() @ &m : res] =
  Pr[DoubleSpendGame(A).main() @ &m : is_collision DoubleSpendGame.result.`1 DoubleSpendGame.result.`2].
- byequiv => //;
  proc;
  inline *;
  wp;
  call A_attack_coupling;
  skip => />.

(* Step 2: Relate BindingGame to DoubleSpendGame's binding sub-event *)
have hbind : Pr[BindingGame(BindingReduction(A)).main() @ &m : res] =
  Pr[DoubleSpendGame(A).main() @ &m : is_binding_break DoubleSpendGame.m1 DoubleSpendGame.m2].
- byequiv => //;
  proc;
  inline *;
  wp;
  call A_attack_coupling;
  skip => />.

(* Step 3: Probability monotonicity (Winning DS implies one of the sub-events) *)
have hmon : Pr[DoubleSpendGame(A).main() @ &m : res] <=
  Pr[DoubleSpendGame(A).main() @ &m :
       is_collision DoubleSpendGame.result.`1 DoubleSpendGame.result.`2 \/
       is_binding_break DoubleSpendGame.m1 DoubleSpendGame.m2].
- byequiv (: ={glob A} ==>
    res{1} =>
    is_collision DoubleSpendGame.result{2}.`1 DoubleSpendGame.result{2}.`2 \/
    is_binding_break DoubleSpendGame.m1{2} DoubleSpendGame.m2{2}) => //.
  proc;
  wp;
  call A_attack_coupling;
  skip => />.
  smt(ds_implies_coll_or_bind). (* Apply our pure mathematical lemma *)

(* Step 4: Union bound on the disjunctive event *)
have hunion :
  Pr[DoubleSpendGame(A).main() @ &m :
       is_collision DoubleSpendGame.result.`1 DoubleSpendGame.result.`2 \/
       is_binding_break DoubleSpendGame.m1 DoubleSpendGame.m2] <=
  Pr[DoubleSpendGame(A).main() @ &m : is_collision DoubleSpendGame.result.`1 DoubleSpendGame.result.`2] +
  Pr[DoubleSpendGame(A).main() @ &m : is_binding_break DoubleSpendGame.m1 DoubleSpendGame.m2].
- rewrite Pr[mu_or].
  (* Prove the intersection is >= 0 by bounding it below by Pr[false] *)
  have h_ge0 : 0%r <= Pr[DoubleSpendGame(A).main() @ &m :
       is_collision DoubleSpendGame.result.`1 DoubleSpendGame.result.`2 /\
       is_binding_break DoubleSpendGame.m1 DoubleSpendGame.m2].
  + have Hzero : Pr[DoubleSpendGame(A).main() @ &m : false] = 0%r by rewrite Pr[mu_false].
    rewrite -Hzero.
    byequiv => //;
    proc;
    wp;
    call A_attack_coupling;
    skip => />.
  smt().

(* Step 5: Chain the inequalities hmon hunion hcoll hbind together *)
smt().

qed.

end section DoubleSpendSecurity.

(*
Security bounds: For any double-spending adversary A:

Adv^ds_Unicity(A) <= Adv^coll_H(CollisionReduction(A)) + Adv^bind_Com(BindingReduction(A))

Double-spending security reduces to:
1. Collision resistance of the hash function H
2. Computational binding of the commitment scheme

TL;DR: A party can double-spend his token in Unicity system only if he is able to
       either break the collision resistance of the hash function or break the
       binding property of the commitment scheme.
*)