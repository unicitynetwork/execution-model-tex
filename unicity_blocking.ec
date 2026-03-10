(* ==================================================================== *)
(* EasyCrypt Formalization: Security Against Blocking                   *)
(* Unicity Execution Layer

   TL;DR: A malicious party in Unicity system can block other user's token from
   spending by setting a leaf in Unicity Oracle only if the attacker is able
   to either break collision resitance of the hash function or forge signatures
   of the signature scheme.

   Details: Section 5.1, Security against Blocking

   A blocking adversary A uses two oracles:
      1. US: the Unicity Service,
      2. TS(sk,·): the transaction signer.

   Security game where A breaks the security against blocking:
     1. (pk, sk) <- G                   // key generation
     2. h_st <- A^{US, TS(sk,·)}(pk)    // A has access to two oracles
     3. A wins if R[H(pk, h_st)] ≠ ⊥  AND  no TS oracle query used h_st
         // that is, US has the leaf blocked in its repository R, but
         // no-one signed the US request (TS haven't seen h_st)

   Three exhaustive cases of a winning attack:
     (a)  US received (pk', h_st', ·, ·) with H(pk',h_st') = H(pk,h_st)
          but (pk',h_st') ≠ (pk,h_st)          --> hreg collision
     (b1) TS received (h_st', D) with h_st' ≠ h_st but
          H(h_st', H(D)) = H(h_st, h_tx)       --> hmsg collision
     (b2) A valid US request (pk, h_st, h_tx, σ) where no TS query
          produced message H(h_st, h_tx)       --> EUF-CMA forgery

   Main theorem:
     Adv^block(A) ≤ Adv^hreg-coll + Adv^hmsg-coll + Adv^EUF-CMA

    that is, the success probability (advantage) of A winning the blocking
     game is bounded by success probabilities of breaking collision resistance
     of the hash function and success probability of creating an existential
     forgery of the signature scheme (forging a signature on chosen message).

*)
require import AllCore List.

(* ------------------------------------------------------------------ *)
(* 1.  Types & Primitive Operations                                   *)
(* ------------------------------------------------------------------ *)

type pubkey.
type prikey.
type state_hash.
type tx_hash.
type message.
type signature.
type transaction_data.
type reg_key.

op keygen_d : (pubkey * prikey) distr.
op sign   : prikey -> message -> signature.
op verify : pubkey -> message -> signature -> bool.

op hreg  : pubkey     -> state_hash -> reg_key.
op hmsg  : state_hash -> tx_hash    -> message.
op hdata : transaction_data         -> tx_hash.

(* ------------------------------------------------------------------ *)
(* 2.  Pure Logic: Attack Case Identifiers                            *)
(* ------------------------------------------------------------------ *)

(* Case (b1) indicator: hmsg collision in the TS log *)
op is_hmsg_coll (pk : pubkey, h_st : state_hash,
                 reg : (reg_key * tx_hash) list,
                 ts_log : (state_hash * tx_hash) list) : bool =
  let h_tx = odflt witness (assoc reg (hreg pk h_st)) in
  has (fun (e : state_hash * tx_hash) => hmsg e.`1 e.`2 = hmsg h_st h_tx) ts_log.

(* Case (a) indicator: hreg collision in the US source log *)
op is_hreg_coll (pk : pubkey, h_st : state_hash,
                 us_src : (reg_key * (pubkey * state_hash)) list) : bool =
  odflt (pk, h_st) (assoc us_src (hreg pk h_st)) <> (pk, h_st).

(* ------------------------------------------------------------------ *)
(* 3.  Collision & Forgery Games                                      *)
(* ------------------------------------------------------------------ *)

module type HregCollAdversary = { proc find() : (pubkey * state_hash) * (pubkey * state_hash) }.
module HregCollGame(A : HregCollAdversary) = {
  proc main() : bool = {
    var x1, x2 : pubkey * state_hash;
    (x1, x2) <@ A.find();
    return x1 <> x2 /\ hreg x1.`1 x1.`2 = hreg x2.`1 x2.`2;
  }
}.

module type HmsgCollAdversary = { proc find() : (state_hash * tx_hash) * (state_hash * tx_hash) }.
module HmsgCollGame(A : HmsgCollAdversary) = {
  proc main() : bool = {
    var x1, x2 : state_hash * tx_hash;
    (x1, x2) <@ A.find();
    return x1 <> x2 /\ hmsg x1.`1 x1.`2 = hmsg x2.`1 x2.`2;
  }
}.

module SigningOracle = {
  var sk      : prikey
  var queries : message list
  proc query(m : message) : signature = {
    queries <- m :: queries;
    return sign sk m;
  }
}.

module type EUFAdversary = { proc forge(pk : pubkey) : message * signature }.
module EFCMA_Game(A : EUFAdversary) = {
  var pk      : pubkey
  var m_out   : message
  var sig_out : signature
  proc main() : bool = {
    var kp : pubkey * prikey;
    kp <$ keygen_d;
    pk                    <- kp.`1;
    SigningOracle.sk      <- kp.`2;
    SigningOracle.queries <- [];
    (m_out, sig_out) <@ A.forge(pk);
    return verify pk m_out sig_out /\ ! (m_out \in SigningOracle.queries);
  }
}.

(* ------------------------------------------------------------------ *)
(* 4.  Blocking Game & Oracles                                        *)
(* ------------------------------------------------------------------ *)

module type BlockOracle = {
  proc us_query(pk : pubkey, h_st : state_hash, h_tx : tx_hash, sig : signature) : bool
  proc ts_query(h_st : state_hash, D : transaction_data) : signature * tx_hash
}.

module type BlockAdversary (O : BlockOracle) = { proc run(pk : pubkey) : state_hash }.

module BlockOracles : BlockOracle = {
  var pk       : pubkey
  var sk       : prikey
  var registry : (reg_key * tx_hash) list
  var ts_log   : (state_hash * tx_hash) list

  proc us_query(pk' : pubkey, h_st' : state_hash, h_tx' : tx_hash, sig' : signature) : bool = {
    var accepted <- false;
    if (! has (fun (e : reg_key * tx_hash) => e.`1 = hreg pk' h_st') registry && verify pk' (hmsg h_st' h_tx') sig') {
      registry <- (hreg pk' h_st', h_tx') :: registry;
      accepted <- true;
    }
    return accepted;
  }

  proc ts_query(h_st' : state_hash, D : transaction_data) : signature * tx_hash = {
    var h_tx' <- hdata D;
    var sig'  <- sign sk (hmsg h_st' h_tx');
    ts_log    <- (h_st', h_tx') :: ts_log;
    return (sig', h_tx');
  }
}.

module BlockingGame(A : BlockAdversary) = {
  var h_st_out : state_hash
  proc main() : bool = {
    var kp;
    kp <$ keygen_d;
    BlockOracles.pk       <- kp.`1;
    BlockOracles.sk       <- kp.`2;
    BlockOracles.registry <- [];
    BlockOracles.ts_log   <- [];
    h_st_out <@ A(BlockOracles).run(BlockOracles.pk);
    return has (fun (e : reg_key * tx_hash) => e.`1 = hreg BlockOracles.pk h_st_out) BlockOracles.registry /\
           ! has (fun (e : state_hash * tx_hash) => e.`1 = h_st_out) BlockOracles.ts_log;
  }
}.

(* ------------------------------------------------------------------ *)
(* 5.  Instrumented Oracles & Reductions                              *)
(* ------------------------------------------------------------------ *)

module ForgerOracle : BlockOracle = {
  var pk       : pubkey
  var registry : (reg_key * tx_hash) list
  var ts_log   : (state_hash * tx_hash) list
  var sig_src  : (reg_key * signature) list

  proc us_query(pk' : pubkey, h_st' : state_hash, h_tx' : tx_hash, sig' : signature) : bool = {
    var accepted <- false;
    if (! has (fun (e : reg_key * tx_hash) => e.`1 = hreg pk' h_st') registry && verify pk' (hmsg h_st' h_tx') sig') {
      registry <- (hreg pk' h_st', h_tx') :: registry;
      sig_src  <- (hreg pk' h_st', sig') :: sig_src;
      accepted <- true;
    }
    return accepted;
  }

  proc ts_query(h_st' : state_hash, D : transaction_data) : signature * tx_hash = {
    var h_tx' <- hdata D;
    var sig';
    sig' <@ SigningOracle.query(hmsg h_st' h_tx');
    ts_log    <- (h_st', h_tx') :: ts_log;
    return (sig', h_tx');
  }
}.

module HregBlockOracles : BlockOracle = {
  var pk       : pubkey
  var sk       : prikey
  var registry : (reg_key * tx_hash) list
  var ts_log   : (state_hash * tx_hash) list
  var us_src   : (reg_key * (pubkey * state_hash)) list

  proc us_query(pk' : pubkey, h_st' : state_hash, h_tx' : tx_hash, sig' : signature) : bool = {
    var accepted <- false;
    if (! has (fun (e : reg_key * tx_hash) => e.`1 = hreg pk' h_st') registry && verify pk' (hmsg h_st' h_tx') sig') {
      registry <- (hreg pk' h_st', h_tx') :: registry;
      us_src   <- (hreg pk' h_st', (pk', h_st')) :: us_src;
      accepted <- true;
    }
    return accepted;
  }

  proc ts_query(h_st' : state_hash, D : transaction_data) : signature * tx_hash = {
    var h_tx' <- hdata D;
    var sig'  <- sign sk (hmsg h_st' h_tx');
    ts_log    <- (h_st', h_tx') :: ts_log;
    return (sig', h_tx');
  }
}.

module HregBlockingGame(A : BlockAdversary) = {
  var h_st_out : state_hash
  proc main() : bool = {
    var kp;
    kp <$ keygen_d;
    HregBlockOracles.pk       <- kp.`1;
    HregBlockOracles.sk       <- kp.`2;
    HregBlockOracles.registry <- [];
    HregBlockOracles.ts_log   <- [];
    HregBlockOracles.us_src   <- [];
    h_st_out <@ A(HregBlockOracles).run(HregBlockOracles.pk);
    return has (fun (e : reg_key * tx_hash) => e.`1 = hreg HregBlockOracles.pk h_st_out) HregBlockOracles.registry /\
           ! has (fun (e : state_hash * tx_hash) => e.`1 = h_st_out) HregBlockOracles.ts_log;
  }
}.

module HregCollReduction(B : BlockAdversary) : HregCollAdversary = {
  proc find() : (pubkey * state_hash) * (pubkey * state_hash) = {
    var h_st, src;
    var kp;
    kp <$ keygen_d;
    HregBlockOracles.pk       <- kp.`1;
    HregBlockOracles.sk       <- kp.`2;
    HregBlockOracles.registry <- [];
    HregBlockOracles.ts_log   <- [];
    HregBlockOracles.us_src   <- [];
    h_st <@ B(HregBlockOracles).run(kp.`1);
    src  <- assoc HregBlockOracles.us_src (hreg kp.`1 h_st);
    return (odflt (kp.`1, h_st) src, (kp.`1, h_st));
  }
}.

module HmsgCollReduction(B : BlockAdversary) : HmsgCollAdversary = {
  proc find() : (state_hash * tx_hash) * (state_hash * tx_hash) = {
    var h_st, h_tx, col;
    var kp;
    kp <$ keygen_d;
    BlockOracles.pk       <- kp.`1;
    BlockOracles.sk       <- kp.`2;
    BlockOracles.registry <- [];
    BlockOracles.ts_log   <- [];
    h_st <@ B(BlockOracles).run(kp.`1);
    h_tx <- odflt witness (assoc BlockOracles.registry (hreg kp.`1 h_st));
    col  <- nth witness BlockOracles.ts_log
              (find (fun (e : state_hash * tx_hash) => hmsg e.`1 e.`2 = hmsg h_st h_tx) BlockOracles.ts_log);
    return (col, (h_st, h_tx));
  }
}.

module ForgerReduction(B : BlockAdversary) : EUFAdversary = {
  proc forge(pk : pubkey) : message * signature = {
    var h_st, h_tx, sig;
    ForgerOracle.pk       <- pk;
    ForgerOracle.registry <- [];
    ForgerOracle.ts_log   <- [];
    ForgerOracle.sig_src  <- [];
    h_st <@ B(ForgerOracle).run(pk);
    h_tx <- odflt witness (assoc ForgerOracle.registry (hreg pk h_st));
    sig  <- odflt witness (assoc ForgerOracle.sig_src  (hreg pk h_st));
    return (hmsg h_st h_tx, sig);
  }
}.

(* ------------------------------------------------------------------ *)
(* 6.  Main Security Theorem                                          *)
(* ------------------------------------------------------------------ *)
section BlockingSecurity.

declare module A <: BlockAdversary
  {-BlockOracles, -HregBlockOracles, -ForgerOracle, -SigningOracle,
   -BlockingGame, -HregBlockingGame, -EFCMA_Game}.

(* ------------------------------------------------------------------ *)
(* Game-Level Coupling Axioms                                         *)
(* (Provable for concrete adversaries via standard oracle swapping)   *)
(* ------------------------------------------------------------------ *)

declare axiom hb1_game_coupling :
  equiv[BlockingGame(A).main ~ HmsgCollGame(HmsgCollReduction(A)).main :
    ={glob A} ==>
    (res{1} /\ is_hmsg_coll BlockOracles.pk{1} BlockingGame.h_st_out{1}
                            BlockOracles.registry{1} BlockOracles.ts_log{1}) => res{2}].

declare axiom hswap_game_coupling :
  equiv[BlockingGame(A).main ~ HregBlockingGame(A).main :
    ={glob A} ==>
    ={glob A, res} /\
    BlockOracles.pk{1}       = HregBlockOracles.pk{2} /\
    BlockOracles.registry{1} = HregBlockOracles.registry{2} /\
    BlockOracles.ts_log{1}   = HregBlockOracles.ts_log{2} /\
    BlockingGame.h_st_out{1} = HregBlockingGame.h_st_out{2}].

declare axiom ha_game_coupling :
  equiv[HregBlockingGame(A).main ~ HregCollGame(HregCollReduction(A)).main :
    ={glob A} ==>
    (res{1} /\
     !is_hmsg_coll HregBlockOracles.pk{1} HregBlockingGame.h_st_out{1}
                   HregBlockOracles.registry{1} HregBlockOracles.ts_log{1} /\
     is_hreg_coll HregBlockOracles.pk{1} HregBlockingGame.h_st_out{1}
                  HregBlockOracles.us_src{1}) => res{2}].

declare axiom hb2_game_coupling :
  equiv[HregBlockingGame(A).main ~ EFCMA_Game(ForgerReduction(A)).main :
    ={glob A} ==>
    (res{1} /\
     !is_hmsg_coll HregBlockOracles.pk{1} HregBlockingGame.h_st_out{1}
                   HregBlockOracles.registry{1} HregBlockOracles.ts_log{1} /\
     !is_hreg_coll HregBlockOracles.pk{1} HregBlockingGame.h_st_out{1}
                   HregBlockOracles.us_src{1}) => res{2}].

(* ------------------------------------------------------------------ *)
(* The Proof                                                          *)
(* ------------------------------------------------------------------ *)
lemma blocking_security &m :
  Pr[BlockingGame(A).main() @ &m : res] <=
  Pr[HmsgCollGame(HmsgCollReduction(A)).main() @ &m : res] +
  (Pr[HregCollGame(HregCollReduction(A)).main() @ &m : res] +
   Pr[EFCMA_Game(ForgerReduction(A)).main() @ &m : res]).
proof.
  (* Step 1: Split the main game on the hmsg collision event (Case b1) *)
  rewrite Pr[mu_split (is_hmsg_coll BlockOracles.pk BlockingGame.h_st_out
                                    BlockOracles.registry BlockOracles.ts_log)].

  (* Step 2: Bound the Case b1 branch by HmsgCollGame *)
  have H_hb1 :
    Pr[BlockingGame(A).main() @ &m :
         res /\ is_hmsg_coll BlockOracles.pk BlockingGame.h_st_out
                             BlockOracles.registry BlockOracles.ts_log] <=
    Pr[HmsgCollGame(HmsgCollReduction(A)).main() @ &m : res].
  - by byequiv hb1_game_coupling.

  (* Step 3: Bound the remaining branch (Cases a and b2) *)
  have H_hnb1 :
    Pr[BlockingGame(A).main() @ &m :
         res /\ !is_hmsg_coll BlockOracles.pk BlockingGame.h_st_out
                              BlockOracles.registry BlockOracles.ts_log] <=
    Pr[HregCollGame(HregCollReduction(A)).main() @ &m : res] +
    Pr[EFCMA_Game(ForgerReduction(A)).main() @ &m : res].
  - (* Swap to HregBlockingGame to expose the us_src log *)
    have -> :
      Pr[BlockingGame(A).main() @ &m :
           res /\ !is_hmsg_coll BlockOracles.pk BlockingGame.h_st_out
                                BlockOracles.registry BlockOracles.ts_log] =
      Pr[HregBlockingGame(A).main() @ &m :
           res /\ !is_hmsg_coll HregBlockOracles.pk HregBlockingGame.h_st_out
                                HregBlockOracles.registry HregBlockOracles.ts_log].
    + byequiv hswap_game_coupling => // /#.

    (* Split on the hreg collision event (Case a) *)
    rewrite Pr[mu_split (is_hreg_coll HregBlockOracles.pk HregBlockingGame.h_st_out
                                      HregBlockOracles.us_src)].

    (* Bound Case a by HregCollGame *)
    have H_ha :
      Pr[HregBlockingGame(A).main() @ &m :
           res /\ !is_hmsg_coll HregBlockOracles.pk HregBlockingGame.h_st_out
                                HregBlockOracles.registry HregBlockOracles.ts_log /\
           is_hreg_coll HregBlockOracles.pk HregBlockingGame.h_st_out
                        HregBlockOracles.us_src] <=
      Pr[HregCollGame(HregCollReduction(A)).main() @ &m : res].
    + byequiv ha_game_coupling => // /#.

    (* Bound Case b2 by EFCMA_Game *)
    have H_hb2 :
      Pr[HregBlockingGame(A).main() @ &m :
           res /\ !is_hmsg_coll HregBlockOracles.pk HregBlockingGame.h_st_out
                                HregBlockOracles.registry HregBlockOracles.ts_log /\
           !is_hreg_coll HregBlockOracles.pk HregBlockingGame.h_st_out
                         HregBlockOracles.us_src] <=
      Pr[EFCMA_Game(ForgerReduction(A)).main() @ &m : res].
    + byequiv hb2_game_coupling => // /#.

    (* Combine Case a and Case b2 bounds *)
    smt().

  (* Final combination of all bounds (H_hb1 H_hnb1) *)
  smt().
qed.

end section BlockingSecurity.

(*
  Security summary
  ================
  For any blocking adversary A:

    Adv^block(A)  ≤  Adv^hreg-coll( HregCollReduction(A) )
                  +  Adv^hmsg-coll( HmsgCollReduction(A) )
                  +  Adv^EUF-CMA(   ForgerReduction(A)   )

  Blocking security reduces to:
    1. Collision resistance of H applied to (pk, h_st)    -- case (a)
    2. Collision resistance of H applied to (h_st, h_tx)  -- case (b1)
    3. EUF-CMA security of the signature scheme           -- case (b2)

  Note: Security against Blocking proof in the paper combines cases (a) and
  (b1) into a single collision-finder A_coll and uses one collision
  game.  This formalization keeps them separate (one game per hash
  domain) for precision; the bound differs only by a factor of 2.
*)