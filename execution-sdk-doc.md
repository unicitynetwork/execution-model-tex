# Unicity Protocol TypeScript SDK - Data Structures Specification

## Core Cryptographic Primitives

### Hash Function

```typescript
// Hash algorithm: SHA-256 ($H$ in the paper)
type Hash = ...
// Random blinding mask for state transitions ($x$ in paper)
type BlindingMask = ...  // at least 128 bits of entropy
```

### Predicates and Witnesses

```typescript
/**
 * Predicate: Programmable spending condition
 * Corresponds to $\predi$ from the paper
 * Function signature: predicate(systime, message, witness) → boolean
 */
type Predicate = ...

/**
 * Witness: Data proving predicate satisfaction
 * Corresponds to $\sigma$ from the paper
 * Replaces signatures in the generalized model
 */
type Witness = ...
```

## Token State and Ownership

### Token State Structure

```typescript
/**
 * TokenState represents the spending condition and state of a token
 * Corresponds to $(\predi, \auxd, h_{st})$ from the paper
 */
interface TokenState {
  /** Spending condition predicate ($\predi$ in paper) */
  predicate: Predicate;

  /** Auxiliary data accessible to predicate ($\auxd$ in paper) */
  auxiliaryData: bytes;

  /** Rolling state identifier, at genesis h_st_0 = h(id, MINT_SUFFIX),
   *  then h_st_{i+1} = h(x, h_st_i) */
  stateHash: Hash;
}

/**
 * State identifier uniquely identifies a token state
 * Corresponds to $H(\predi, h_{st})$ in the paper
 */
type StateId = Hash;
```

## Transaction Data Structures

### Transaction Data

```typescript
/**
 * Transaction data structure for token transfers
 * Corresponds to $D = (\predi', \auxd', x)$ from the paper
 * Unified structure for both mint and transfer transactions
 */
interface TransactionData {
  /** Recipient's spending predicate ($\predi'$ in paper) */
  recipientPredicate: Predicate;

  /** Auxiliary data for the next token state ($\auxd'$ in paper) */
  recipientAuxiliaryData: bytes;

  /** Random blinding mask for privacy and state evolution ($x$ in paper) */
  blindingMask: BlindingMask;  // NULL if mint transaction

  // Additional fields for mint transactions (zero/empty for transfers)
  mintTransactionData: MintTransactionData?;
}

MintTransactionData := {
  tokenId: TokenId,              // Unique token identifier
  tokenType: TokenType,          // Token class identifier
  tokenData: bytes,              // Immutable token data
  coinData: CoinData?,           // Optional payload of fungible coin + value
  reason: Serializable?          // Optional mint justification
  // bridged asset: burn or locking proof / reference
}

CoinData := {
  coinId: CoinId,
  balance: bigint;
}

// CoinId is a 32-byte identifier for a specific coin type
type CoinId = Uint8Array;  // 32 bytes

/**
 * Transaction data hash calculation
 * In the paper: $h_{tx} = \commitc(H(D))$
 * With unity commitment: $h_{tx} = H(D)$
 */
function calculateTransactionHash(d: TransactionData): Hash {
  return sha256(encodeTransactionData(d));
}
```

### Transaction Structure

```typescript
/**
 * Complete transaction structure
 * Corresponds to $T = (h_{st}, D)$ from the paper
 */
interface Transaction {
  /** Current state hash before executing transaction ($h_{st}$ in paper) */
  currentStateHash: Hash;

  /** Transaction data containing recipient predicate and other details */
  transactionData: TransactionData;
}
```

## Certified Transaction and Proofs

### Certified Transaction

```typescript
/**
 * Certified transaction with Unicity Service proofs
 * Corresponds to $(T, \sigma, h_{tx}, \pi)$ from the paper
 */
interface CertifiedTransaction {
  /** The transaction being certified ($T$) */
  transaction: Transaction;

  /** Witness satisfying current predicate ($\sigma$ in paper) */
  witness: Witness;

  /** Transaction data hash ($h_{tx}$ in paper) */
  transactionHash: Hash;

  /** Inclusion proof from Unicity Service ($\pi$ in paper) */
  inclusionProof: InclusionProof;
}

/**
 * Inclusion proof from Unicity Service
 * Proves that a state transition was registered
 */
interface InclusionProof {
  /** Cryptographic proof data ($\pi$ in paper) */
  /** Versioned. Documented elsewhere */
}
```

## Unicity Service Interface

### Service Request Structure

```typescript
/**
 * Request to Unicity Service for state transition certification
 * Corresponds to $Q = (\predi, h_{st}, h_{tx}, \sigma)$ from the paper
 */
interface UnicityServiceRequest {
  /** Current spending predicate ($\predi$ in paper) */
  predicate: Predicate;

  /** Current state hash ($h_{st}$ in paper) */
  currentStateHash: Hash;

  /** Transaction data hash ($h_{tx}$ in paper) */
  transactionHash: Hash;

  /** Witness satisfying the predicate ($\sigma$ in paper) */
  witness: Witness;
}

/**
 * Response from Unicity Service
 */
interface UnicityServiceResponse {
  /** Whether the request was accepted */
  success: boolean;

  /** Inclusion proof if successful ($\pi$ in paper) */
  inclusionProof?: InclusionProof;

  /** Error message if failed */
  error?: string;
}
```

### Abstract Unicity Service Interface

```typescript
/**
 * Abstract interface for Unicity Service interaction
 * Modeled as key-value store $R$ in the paper where:
 * - Keys are $H(\predi, h_{st})$ (StateId)
 * - Values are $h_{tx}$ (transaction hashes)
 */
interface UnicityService {
  /**
   * Submit a state transition request
   * Service checks:
   * 1. $R[H(\predi, h_{st})] = \bot$ (not already spent)
   * 2. $\predi(\systime, H(h_{st}, h_{tx}), \sigma) = 1$ (predicate satisfied)
   * If both pass: $R[H(\predi, h_{st})] \gets h_{tx}$
   */
  submitRequest(request: UnicityServiceRequest): Promise<UnicityServiceResponse>;

  /**
   * Verify inclusion proof (self-contained, does not access the service)
   * Corresponds to $\univer(k, v, \pi)$ from the paper
   */
  verifyInclusionProof(
    stateId: StateId,
    transactionHash: Hash,
    proof: InclusionProof
  ): Promise<boolean>;

  /**
   * Extract system time from proof (self-contained, does not access the service)
   * Corresponds to $\exttime(\pi)$ from the paper
   */
  extractTime(proof: InclusionProof): number;
}
```

## Token Structure and History

### Complete Token

```typescript
/**
 * Complete token with full transaction history
 */
interface Token {
  /** Protocol version */
  version: string;

  /** Current state of the token */
  currentState: TokenState;

  /** Genesis/mint transaction that created the token */
  genesis: CertifiedTransaction;

  /** Ordered history of state transitions */
  transactionHistory: CertifiedTransaction[];
}
```

## Verification

### Transaction Verification Algorithm

```typescript
/**
 * Verify a certified transaction in a given state
 * Corresponds to $\certver(T, \sigma, h_{tx}, \pi; \predi, \auxd, h_{st})$ from paper
 * Returns true if valid, false otherwise
 */
async function verifyCertifiedTransaction(
  certifiedTx: CertifiedTransaction,
  expectedState: TokenState,
  unicityService: UnicityService
): Promise<boolean> {
  const { transaction, witness, transactionHash, inclusionProof } = certifiedTx;

  // Check 1: T.h_st = h_st (current state hash matches)
  if (transaction.currentStateHash !== expectedState.stateHash) {
    return false;
  }

  // Check 2: h_tx = H(T.D) (transaction hash is correct)
  const calculatedHash = calculateTransactionHash(transaction.transactionData);
  if (transactionHash !== calculatedHash) {
    return false;
  }

  // Check 3: predicate(systime, H(h_st, h_tx), witness) = 1
  const systime = unicityService.extractTime(inclusionProof);
  const message = sha256(transaction.currentStateHash + transactionHash);
  if (!evaluatePredicate(expectedState.predicate, systime, message, witness, expectedState.auxiliaryData)) {
    return false;
  }

  // Check 4: univer(H(predicate, h_st), h_tx, pi) = 1
  const stateId = calculateStateId(expectedState.predicate, transaction.currentStateHash);
  return await unicityService.verifyInclusionProof(stateId, transactionHash, inclusionProof);
}

/**
 * Evaluate predicate with given parameters
 * Implementation depends on predicate type
 */
function evaluatePredicate(
  predicate: Predicate,
  systime: number,
  message: Hash,
  witness: Witness,
  auxiliaryData: bytes
): boolean {
  // Implementation-specific: dispatch to appropriate predicate evaluator
  throw new Error("Not implemented - implement predicate evaluation");
}
```

### Token Verification Algorithm

```typescript
/**
 * Verify a token with full transaction history
 * Validates:
 * 1. Genesis/mint transaction
 * 2. All transactions in history
 * 3. Cryptographic links between transactions (state hash evolution)
 * 4. Current state consistency
 */
async function verifyToken(
  token: Token,
  unicityService: UnicityService
): Promise<boolean> {
  // Verify genesis/mint transaction
  if (!await verifyMintTransaction(token.genesis, unicityService)) {
    return false;
  }

  // Extract initial state from genesis transaction
  let currentStateHash = token.genesis.transaction.currentStateHash;
  let currentPredicate = token.genesis.transaction.transactionData.recipientPredicate;
  let currentAuxData = token.genesis.transaction.transactionData.recipientAuxiliaryData;

  // Verify each transaction in the history sequentially
  for (const certifiedTx of token.transactionHistory) {
    const expectedState: TokenState = {
      predicate: currentPredicate,
      auxiliaryData: currentAuxData,
      stateHash: currentStateHash
    };

    if (!await verifyCertifiedTransaction(certifiedTx, expectedState, unicityService)) {
      return false;
    }

    // Compute next state hash: h' = H(h, x)
    const blindingMask = certifiedTx.transaction.transactionData.blindingMask;
    currentStateHash = sha256(currentStateHash + blindingMask);
    currentPredicate = certifiedTx.transaction.transactionData.recipientPredicate;
    currentAuxData = certifiedTx.transaction.transactionData.recipientAuxiliaryData;
  }

  // Verify that final computed state matches token's current state
  if (currentStateHash !== token.currentState.stateHash ||
      currentPredicate !== token.currentState.predicate ||
      currentAuxData !== token.currentState.auxiliaryData) {
    return false;
  }

  return true;
}
```

### Mint Transaction Verification

```typescript
/**
 * Verify a mint transaction (genesis transaction for a token)
 * Uses system mint predicate
 */
async function verifyMintTransaction(
  certifiedTx: CertifiedTransaction,
  unicityService: UnicityService
): Promise<boolean> {
  const { transaction, witness, transactionHash, inclusionProof } = certifiedTx;
  const mintData = transaction.transactionData.mintTransactionData;

  if (!mintData) {
    return false;
  }

  // Check 1: Verify state hash is derived from token ID
  const expectedStateHash = sha256(mintData.tokenId + "MINT_SUFFIX");
  if (transaction.currentStateHash !== expectedStateHash) {
    return false;
  }

  // Check 2: Verify transaction hash = H(D_mint)
  const calculatedHash = calculateTransactionHash(transaction.transactionData);
  if (transactionHash !== calculatedHash) {
    return false;
  }

  // Check 3: Verify mint predicate satisfaction
  const MINT_PREDICATE = getMintPredicate();
  const systime = unicityService.extractTime(inclusionProof);
  const message = sha256(transaction.currentStateHash + transactionHash);
  if (!evaluatePredicate(MINT_PREDICATE, systime, message, witness, null)) {
    return false;
  }

  // Check 4: Verify inclusion proof with mint predicate
  const stateId = calculateStateId(MINT_PREDICATE, transaction.currentStateHash);
  if (!await unicityService.verifyInclusionProof(stateId, transactionHash, inclusionProof)) {
    return false;
  }

  // Application-specific mint validation
  if (!validateMintJustification(mintData)) {
    return false;
  }

  return true;
}

/**
 * Calculate state identifier from predicate and state hash
 * Corresponds to H(predicate, h_st) in the paper
 */
function calculateStateId(predicate: Predicate, stateHash: Hash): StateId {
  return sha256(encodePredicate(predicate) + stateHash);
}

/**
 * Get the system mint predicate
 * This is a well-known constant
 */
function getMintPredicate(): Predicate {
  throw new Error("Not implemented - return system mint predicate");
}

/**
 * Validate mint justification (application-specific)
 */
function validateMintJustification(mintData: MintTransactionData): boolean {
  // Application-specific validation:
  // - Verify bridged asset burn/lock proof
  // - Check authorization for minting
  // - Validate token data format
  throw new Error("Not implemented - implement application-specific mint validation");
}

/**
 * Encode predicate to bytes for hashing
 * Implementation-specific serialization
 */
function encodePredicate(predicate: Predicate): bytes {
  throw new Error("Not implemented - implement predicate serialization");
}
```

## Protocol Flow

### Token Transfer Flow

See the execution layer paper, Appendix A.


## Related Concepts

### Token Payload

See `MintTransactionData` above for token payload structure.

### Token Split

To burn input token, send it to an _always false_ predicate.

### Bridging PoW Alpha

Mint justification for PoW bridging:
- Block number of burn / last tx
- Hash chain from burn / last tx to block header

Verifier runs their own full PoW blockchain node.

### Bridging External Assets

Depends on source blockchain. E.g., Solana: check TX status directly using RPC call.

### Address Format

Options:
- Predicate hash in base58
- P2PKH-style: hash of predicate for shorter addresses

### Naming System (Name Tags)

Use case 1: there is a 3rd party certifying name-pubkey(predicate) pairs. Needs a revocation system and a lookup service.

Use case 2: whoever is 1st to grab a name owns it. Needs sybil, name hoarding protection, e.g. economic.


### Versioning

Version number at highest level of token container structure. Different versions' state do not overlap.
Unicity service versioned using endpoint URI; also version in Unicity Certificate

## Aggregation Service

### Versioning

Different protocol versions use separate endpoint URIs and maintain independent state spaces.

### Data

The Unicity Service maintains a key-value store `R` where:
- **Keys** are state identifiers: `StateId = H(predicate, stateHash)`
- **Values** are transaction data hashes: `transactionHash`; the atomic broadcast protocol needs to store witness as well

The service processes certification requests `Q = (predicate, stateHash, transactionHash, witness)` by:
1. Evaluating the predicate: `predicate(systime, H(stateHash, transactionHash), witness)`
2. Checking that the state hasn't been spent before (uniqueness)
3. Recording the mapping if valid: `R[H(predicate, stateHash)] ← transactionHash`
4. Returning an inclusion proof `π` of the registered state transition (after round completion). SMT hash chain and a certificate from BFT Core.
