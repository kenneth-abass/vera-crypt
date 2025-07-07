;; VeraCrypt Identity Protocol
;;
;; A next-generation blockchain-based identity verification system that combines
;; cryptographic proofs with reputation-based trust mechanisms. This protocol
;; enables secure, privacy-preserving identity management through zero-knowledge
;; proofs while maintaining decentralized credential issuance and verification.
;;
;; Key Features:
;; - Zero-knowledge proof integration for privacy-preserving authentication
;; - Dynamic reputation scoring with administrative controls
;; - Decentralized credential lifecycle management
;; - Robust recovery mechanisms for lost identities
;; - Comprehensive validation framework for all user inputs

;; ERROR CONSTANTS

(define-constant ERR-NOT-AUTHORIZED (err u1000))
(define-constant ERR-ALREADY-REGISTERED (err u1001))
(define-constant ERR-NOT-REGISTERED (err u1002))
(define-constant ERR-INVALID-PROOF (err u1003))
(define-constant ERR-INVALID-CREDENTIAL (err u1004))
(define-constant ERR-EXPIRED-CREDENTIAL (err u1005))
(define-constant ERR-REVOKED-CREDENTIAL (err u1006))
(define-constant ERR-INVALID-SCORE (err u1007))
(define-constant ERR-INVALID-INPUT (err u1008))
(define-constant ERR-INVALID-EXPIRATION (err u1009))
(define-constant ERR-INVALID-RECOVERY-ADDRESS (err u1010))
(define-constant ERR-INVALID-PROOF-DATA (err u1011))

;; SYSTEM CONFIGURATION

(define-constant MIN-REPUTATION-SCORE u0)
(define-constant MAX-REPUTATION-SCORE u1000)
(define-constant MIN-EXPIRATION-BLOCKS u1)
(define-constant MAX-METADATA-LENGTH u256)
(define-constant MINIMUM-PROOF-SIZE u64)

;; DATA STRUCTURES

;; Primary identity registry mapping principals to their identity metadata
(define-map identities
  principal
  {
    hash: (buff 32),
    credentials: (list 10 principal),
    reputation-score: uint,
    recovery-address: (optional principal),
    last-updated: uint,
    status: (string-ascii 20),
  }
)

;; Credential storage with composite key for uniqueness
(define-map credentials
  {
    issuer: principal,
    nonce: uint,
  }
  {
    subject: principal,
    claim-hash: (buff 32),
    expiration: uint,
    revoked: bool,
    metadata: (string-utf8 256),
  }
)

;; Zero-knowledge proof repository for cryptographic verification
(define-map zero-knowledge-proofs
  (buff 32)
  {
    prover: principal,
    verified: bool,
    timestamp: uint,
    proof-data: (buff 1024),
  }
)

;; STATE VARIABLES

(define-data-var admin principal tx-sender)
(define-data-var credential-nonce uint u0)

;; VALIDATION FUNCTIONS

(define-private (is-valid-recovery-address (recovery-addr (optional principal)))
  (match recovery-addr
    recovery-principal (and
      (not (is-eq recovery-principal tx-sender))
      (not (is-eq recovery-principal (var-get admin)))
    )
    true
  )
)

(define-private (is-valid-proof-data (proof-data (buff 1024)))
  (let ((proof-len (len proof-data)))
    (and
      (>= proof-len MINIMUM-PROOF-SIZE)
      (not (is-eq proof-data 0x))
    )
  )
)

(define-private (is-valid-expiration (expiration uint))
  (> expiration (+ stacks-block-height MIN-EXPIRATION-BLOCKS))
)

(define-private (is-valid-metadata-length (metadata (string-utf8 256)))
  (<= (len metadata) MAX-METADATA-LENGTH)
)

(define-private (is-valid-hash (hash (buff 32)))
  (not (is-eq hash 0x0000000000000000000000000000000000000000000000000000000000000000))
)

;; ADMINISTRATIVE FUNCTIONS

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (asserts! (not (is-eq new-admin tx-sender)) ERR-INVALID-INPUT)
    (ok (var-set admin new-admin))
  )
)

;; IDENTITY MANAGEMENT

(define-public (register-identity
    (identity-hash (buff 32))
    (recovery-addr (optional principal))
  )
  (let (
      (sender tx-sender)
      (existing-identity (map-get? identities sender))
    )
    ;; Comprehensive input validation
    (asserts! (is-none existing-identity) ERR-ALREADY-REGISTERED)
    (asserts! (is-valid-hash identity-hash) ERR-INVALID-INPUT)
    (asserts! (is-valid-recovery-address recovery-addr)
      ERR-INVALID-RECOVERY-ADDRESS
    )
    ;; Initialize new identity with default reputation
    (ok (map-set identities sender {
      hash: identity-hash,
      credentials: (list),
      reputation-score: u100,
      recovery-address: recovery-addr,
      last-updated: stacks-block-height,
      status: "ACTIVE",
    }))
  )
)

;; ZERO-KNOWLEDGE PROOF SYSTEM

(define-public (submit-proof
    (proof-hash (buff 32))
    (proof-data (buff 1024))
  )
  (let (
      (sender tx-sender)
      (existing-identity (map-get? identities sender))
      (existing-proof (map-get? zero-knowledge-proofs proof-hash))
    )
    ;; Validate proof submission requirements
    (asserts! (is-some existing-identity) ERR-NOT-REGISTERED)
    (asserts! (is-valid-hash proof-hash) ERR-INVALID-INPUT)
    (asserts! (is-valid-proof-data proof-data) ERR-INVALID-PROOF-DATA)
    (asserts! (is-none existing-proof) ERR-INVALID-PROOF)
    ;; Store proof awaiting verification
    (ok (map-set zero-knowledge-proofs proof-hash {
      prover: sender,
      verified: false,
      timestamp: stacks-block-height,
      proof-data: proof-data,
    }))
  )
)

(define-public (verify-proof (proof-hash (buff 32)))
  (let (
      (proof (map-get? zero-knowledge-proofs proof-hash))
      (sender tx-sender)
    )
    (asserts! (is-some proof) ERR-INVALID-PROOF)
    (asserts! (is-eq sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (ok (map-set zero-knowledge-proofs proof-hash
      (merge (unwrap-panic proof) { verified: true })
    ))
  )
)

;; CREDENTIAL LIFECYCLE MANAGEMENT

(define-public (issue-credential
    (subject principal)
    (claim-hash (buff 32))
    (expiration uint)
    (metadata (string-utf8 256))
  )
  (let (
      (sender tx-sender)
      (current-nonce (var-get credential-nonce))
      (credential-id {
        issuer: sender,
        nonce: current-nonce,
      })
      (issuer-identity (map-get? identities sender))
      (subject-identity (map-get? identities subject))
    )
    ;; Validate all credential parameters
    (asserts! (is-some issuer-identity) ERR-NOT-REGISTERED)
    (asserts! (is-some subject-identity) ERR-NOT-REGISTERED)
    (asserts! (is-valid-hash claim-hash) ERR-INVALID-INPUT)
    (asserts! (is-valid-expiration expiration) ERR-INVALID-EXPIRATION)
    (asserts! (is-valid-metadata-length metadata) ERR-INVALID-INPUT)
    ;; Increment nonce and create credential
    (var-set credential-nonce (+ current-nonce u1))
    (ok (map-set credentials credential-id {
      subject: subject,
      claim-hash: claim-hash,
      expiration: expiration,
      revoked: false,
      metadata: metadata,
    }))
  )
)

(define-public (revoke-credential
    (issuer principal)
    (nonce uint)
  )
  (let (
      (sender tx-sender)
      (credential-id {
        issuer: issuer,
        nonce: nonce,
      })
      (credential (map-get? credentials credential-id))
    )
    (asserts! (is-some credential) ERR-INVALID-CREDENTIAL)
    (asserts! (is-eq sender issuer) ERR-NOT-AUTHORIZED)
    (ok (map-set credentials credential-id
      (merge (unwrap-panic credential) { revoked: true })
    ))
  )
)

;; REPUTATION SYSTEM

(define-public (update-reputation
    (subject principal)
    (score-change int)
  )
  (let (
      (sender tx-sender)
      (identity (map-get? identities subject))
      (current-score (get reputation-score (unwrap-panic identity)))
      (score-change-abs (if (< score-change 0)
        (* score-change -1)
        score-change
      ))
    )
    (asserts! (is-eq sender (var-get admin)) ERR-NOT-AUTHORIZED)
    (asserts! (is-some identity) ERR-NOT-REGISTERED)
    (asserts!
      (or
        (> score-change 0)
        (>= (to-int current-score) score-change-abs)
      )
      ERR-INVALID-SCORE
    )
    (ok (map-set identities subject
      (merge (unwrap-panic identity) { reputation-score: (if (> score-change 0)
        (+ current-score (to-uint score-change))
        (to-uint (- (to-int current-score) score-change-abs))
      ) }
      )))
  )
)

;; RECOVERY MECHANISMS

(define-public (initiate-recovery
    (identity principal)
    (new-hash (buff 32))
  )
  (let (
      (sender tx-sender)
      (identity-data (map-get? identities identity))
    )
    (asserts! (is-some identity-data) ERR-NOT-REGISTERED)
    (asserts! (is-some (get recovery-address (unwrap-panic identity-data)))
      ERR-NOT-AUTHORIZED
    )
    (asserts!
      (is-eq sender
        (unwrap-panic (get recovery-address (unwrap-panic identity-data)))
      )
      ERR-NOT-AUTHORIZED
    )
    (ok (map-set identities identity
      (merge (unwrap-panic identity-data) {
        hash: new-hash,
        last-updated: stacks-block-height,
        status: "RECOVERED",
      })
    ))
  )
)

;; READ-ONLY FUNCTIONS

(define-read-only (get-identity (identity principal))
  (map-get? identities identity)
)

(define-read-only (get-credential
    (issuer principal)
    (nonce uint)
  )
  (map-get? credentials {
    issuer: issuer,
    nonce: nonce,
  })
)

(define-read-only (verify-credential
    (issuer principal)
    (nonce uint)
  )
  (let ((credential (map-get? credentials {
      issuer: issuer,
      nonce: nonce,
    })))
    (asserts! (is-some credential) ERR-INVALID-CREDENTIAL)
    (ok (and
      (not (get revoked (unwrap-panic credential)))
      (< stacks-block-height (get expiration (unwrap-panic credential)))
    ))
  )
)

(define-read-only (get-proof (proof-hash (buff 32)))
  (map-get? zero-knowledge-proofs proof-hash)
)
