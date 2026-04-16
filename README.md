# layerzero-v2-nonce-exhaustion-poc
# [H-02] Permanent DoS on OApp Messaging Paths via `PendingInboundNonces` Window Exhaustion — Any Entity With DVN Verification Access Can Brick a Channel Forever

---

> **Severity:** 🔴 HIGH  
> **Target Contract:** `contracts/protocol/stellar/contracts/endpoint-v2/src/messaging_channel.rs`  
> **Attack Cost:** 255 `verify()` transactions — zero tokens burned  
> **Recoverability:** ❌ NONE — Endpoint is immutable, no admin reset exists  
> **Chain Exploitable:** ✅ Yes — amplified by PoC 1 (DVN Replay) for zero-cost setup

---
