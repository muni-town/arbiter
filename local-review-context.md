# Arbiter-server second-round review context

Review the current state of `crates/arbiter-server/` (source + tests) and `SERVER_PLAN.md` in the repo at /home/zicklag/git/muni-town/leaf-0.4.

`lexicons/town/muni/arbiter/proxy.json` is owned by another agent — ignore it.

## Background

This is a second review round. A prior reviewer found three issues; those were fixed. Verify the fixes and look for anything new.

### Original review findings (round 1)
Critical: C1 re-provisioning/record-overwrite; C2 monotonic-rev bypass. High: H3 request/response limits; H4 TLS (accepted: reverse proxy); H5 remote-call bound. Medium: M6 plaintext creds (accepted: deferred); M7 permissive CORS (accepted: arbitrary web clients); M8 session cache (accepted); M9 recovery-admin barrier (accepted per plan); M10 PDS signing-key cache (NOT fixed). Low: random_secret docs; create_arbiter orphan; startup retries; putRecord swap; recovery-admin errors not cached.

### User decisions (round 1)
App-password holders may take over stewards. Rev only needs a load-time floor from the PDS (getRepoStatus), fallback timestamp. Add request+response size limits. Reverse proxy does TLS. Limit policy to 12 remote calls. Encryption-at-rest deferred. Keep permissive CORS. Keep valid session until invalid. resetPolicy is the path to install/recover policy.

### Mid-work tweaks (authoritative where they conflict)
- Rev model is floor-only: a single rev_floor per arbiter set at load time (PDS head via getRepoStatus, fallback Tid::now). No per-key revs map. is_newer(did, rev) rejects rev <= floor; every accepted event re-runs load_and_onboard which resets the floor to the fresh PDS head.
- No default policy: createArbiter/createAppPasswordArbiter do NOT write any policy and do NOT call load_and_onboard; arbiter stays offline until resetPolicy installs the first policy.
- Provisioning: both create paths persist credentials BEFORE record writes; service/recovery writes use idempotent putRecord with a 5-attempt retry loop.
- Optimistic concurrency: resetPolicy fetches the REPO HEAD commit CID via getLatestCommit and passes it as putRecord swap_commit (guards the first write too).

## Round-1 reviewer's findings (all three were fixed)

1. **Concurrent policy reloads can regress active policy + rev floor** (state.rs). is_newer checked the floor under a read lock, then load_and_onboard fetched PDS state outside the lock and onboard overwrote floor+policy unconditionally. FIX: onboard is now floor-conditional — replaces an existing arbiter only when incoming floor >= current floor.
2. **Initial resetPolicy had no compare-and-swap protection** (handlers.rs). swap_record was None when no root policy record existed. FIX: switch to repo head commit CID via getLatestCommit as putRecord swap_commit, which guards the first write too.
3. **Mock PDS ignored swapRecord/swapCommit** (tests/integration.rs), so the CAS path wasn't exercised. FIX: mock tracks per-repo head CIDs, rejects stale swapCommit (InvalidSwap/409), advances head on write; added get_latest_commit route; new test put_record_rejects_stale_swap_commit.

## Your task

Verify the three fixes are correct and complete, then review the whole server again for any NEW bugs, regressions, or soundness concerns. Be adversarial: look for edge cases the fixes might have missed.

Focus areas:
- The floor-conditional onboard: is the >= comparison right? What about the (Some,_)/(None,_)/(Some,None) match arms? Any way a stale load still wins, or a legit load gets dropped?
- The swap_commit CAS: is getLatestCommit the right call? Does the mock correctly model a real PDS? Could the CAS introduce a new failure mode (e.g. resetPolicy now fails when the repo moved for an unrelated reason)?
- The mock PDS: does enforcing swapCommit break any other test that does putRecord without swapCommit? Is the head-advance model faithful?
- Overall: any remaining correctness/security gaps beyond M10 (PDS signing-key cache) and the accepted decisions?

Run `cargo build -p arbiter-server` and `cargo test -p arbiter-server` and report results.

Do NOT modify any files. Return a written review: per-finding status (FIXED/PARTIAL/NOT-FIXED) for the three round-1 findings, then a list of any NEW findings with severity and evidence (file:line), then overall correctness verdict.