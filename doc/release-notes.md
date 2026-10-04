Bells Core 3.1.1rc2 (release candidate 2)
======================================

This candidate includes the 3.1 development changes and fixes for header
compatibility, opcode signature-operation accounting, AuxPoW invalid-block
caching, and P2SH transaction relay policy described below.

Release downloads: <https://github.com/Nintondo/bellscoinV3/releases>

Report bugs: <https://github.com/Nintondo/bellscoinV3/issues>

Consensus and Activation
=======================

Header compatibility
--------------------

- Restores the header-version acceptance rules used by Bells 3.0.0. Previously
  valid versions, including the base-zero AuxPoW header `0x00100100`, remain valid
  both before and after opcode activation.
- The versionbits marker determines whether a header signals support. It is not
  an additional requirement for block validity after activation. Activated script
  rules apply to every block, regardless of header version or signaling.
- Header presynchronization accounts for Bells' averaging-window retarget rules
  after the transition to per-block difficulty adjustment.

Opcode deployment
-----------------

The existing `opcat` deployment uses the following mainnet settings:

| Setting | Value |
| --- | --- |
| Signaling bit | 2 |
| Start median time past | October 1, 2026, 00:00 UTC (`1790812800`) |
| Timeout median time past | April 1, 2027, 00:00 UTC (`1806537600`) |
| Signaling threshold | 9,576 of 10,080 blocks (95%) |
| Minimum activation height | 1,300,320 |

A successful signaling period locks in the deployment. Activation follows a
lock-in period and cannot occur below the minimum height; that height alone does
not force activation. Only signaling in eligible STARTED periods counts. Votes
require both the versionbits marker and bit 2.

At a period boundary, reaching the threshold takes precedence over timeout.
Timeout ends an unsuccessful signaling attempt; it does not expire rules that
have already locked in or activated. Continued signaling is not required after
activation. Testnet, signet and regtest retain their separate deployment settings.

The deployment enables:

| Opcode | Supported script contexts |
| --- | --- |
| `OP_CAT` | Tapscript; concatenated elements are limited to 520 bytes |
| `OP_CHECKTEMPLATEVERIFY` (former `OP_NOP4`) | Legacy, P2SH, witness v0 and tapscript |
| `OP_INTERNALKEY` | Tapscript |
| `OP_CHECKSIGFROMSTACK` | Tapscript |
| `OP_CHECKSIGFROMSTACKVERIFY` (former `OP_NOP5`) | Legacy, P2SH, witness v0 and tapscript |

`OP_CHECKTEMPLATEVERIFY` checks a 32-byte template hash without consuming its
argument. Other argument lengths retain no-op consensus behavior, subject to the
existing script limits; an empty input stack fails after activation.
`OP_CHECKSIGFROMSTACKVERIFY` verifies a signature
without consuming its three stack arguments, preserving the stack effect of the
former NOP. CAT and INTERNALKEY remain unavailable in legacy and witness-v0 scripts.

Signature-operation accounting
------------------------------

- Before activation, former NOP5 operations retain their original consensus cost.
  This prevents premature `bad-blk-sigops` rejection, including when those opcodes
  occur in an unexecuted branch or an unspendable output.
- After activation, CSFSVERIFY is included in legacy, P2SH and witness-v0 sigop
  accounting. Tapscript enforces its execution validation budget. Coinbase
  accounting in block templates follows the deployment state.
- P2SH relay policy explicitly counts CSFSVERIFY toward its 15-sigop limit per
  redeem script, including in mixed CHECKSIG/CSFSVERIFY scripts. This standardness
  rule is separate from block consensus and does not wait for activation.

AuxPoW validation
-----------------

Overweight blocks containing AuxPoW parent-coinbase witness are rejected without
permanently marking the shared Bells block hash invalid. Parent-coinbase witness
is not committed by that block hash or by the parent coinbase txid; a rejected
oversized representation must not prevent later acceptance of a valid representation
with the same hash, including after restart.

The fix preserves the existing block-weight limit and acceptance of valid
parent-coinbase witness. It changes failure caching, not the accepted block rules.

Amount and duplicate-transaction checks
--------------------------------------

The 3.1 code retains `MAX_MONEY = 92,000,000 BEL`, compared with 500,000,000 BEL in
3.0.0. This is a consensus amount-range bound, not a cap on cumulative coin issuance.
The Bells-specific BIP30 optimization cutoff remains at height 1,701,897,592;
the recovery changes clarify its historical basis without changing that rule.

How to Upgrade and Check Recovery
================================

Shut down the old node and wait for it to exit completely before replacing the
executables. Start the new version using the intended data directory.

For a node affected by earlier header or block rejection:

1. Check `getblockchaininfo`, `getchaintips`, `getdeploymentinfo` and the rejection
   messages in `debug.log`. Compare the tip and chainwork with a trusted node.
2. Headers that were rejected without being indexed can be requested and validated
   again through normal peer synchronization under the corrected rules.
3. An indexed block already marked invalid can remain rejected after restart.
   If the identified block is valid under the corrected rules and was rejected
   because of one of these fixed problems, use `reconsiderblock "<blockhash>"`
   on that block and let the node evaluate the available chains again.
4. Verify that the node follows the valid chain with the most accumulated work
   and continues advancing. The greatest block height alone is not sufficient.

The upgrade does not automatically clear existing invalid-block flags. Blanket
reconsideration or a routine reindex is not part of this recovery procedure.

The full version identifies this candidate as `3.1.1rc2`; RPC numeric version is
`30101`, and the peer subversion is `/Bells:3.1.1/`. Build identifiers may append a
Git suffix. The peer subversion does not distinguish release candidates.

Storage and Data Directory Compatibility
=======================================

- On Windows, new default data directories use
  `C:\Users\Username\AppData\Local\Bells`. An existing legacy directory under
  `AppData\Roaming\Bells` continues to be used when present.
- Block-file reads and writes apply the key in `blocks/xor.dat`. New empty blocks
  directories use a random key by default; `-blocksxor=0` creates a zero key.
  Existing directories without a key use a zero key. A stored key takes precedence.
- Legacy 3.0.0 data can contain plain block files alongside an unused nonzero
  `xor.dat`. The legacy read fallback detects the plain block framing, replaces
  that key with zeros and retries the read. This is not a general repair for
  arbitrary or mixed block-file formats.
- Older software that does not apply XOR cannot read genuinely XOR-obfuscated
  block files. Keep block files and their matching key together; setting
  `-blocksxor=0` does not convert an existing nonzero-key dataset.
- Pruning-related chainstate flushes can preserve the coins cache instead of
  emptying it unnecessarily.

P2P and Network Changes
=======================

- Version 2 P2P transport support is enabled by default, with compatibility for
  peers using the earlier transport.
- Explicit `-bind` addresses no longer automatically add the default Tor listener.
  Configure an explicit `=onion` bind when a separate Tor listener is required.
  Mainnet's default P2P port is **19919**; the default Tor target remains
  `127.0.0.1:8334`, and the default RPC port remains **8332**.
- Failure to bind an explicitly configured P2P address aborts startup. Failure of
  the automatic IPv6 wildcard bind alone is not fatal.
- UNIX-domain socket paths are supported by `-proxy` and `-onion` on supported
  platforms using `unix:/path/to/socket`. ZMQ publisher options also accept this
  syntax, translated internally to the ZMQ IPC endpoint format.
- `-whitelist` supports `in` and `out` directions for inbound and manually
  established outbound connections.
- Limited one-parent/one-child package relay can consider a low-fee parent with
  a fee-paying child. This does not provide general multi-parent package relay.
  Packages can also be submitted directly through `submitpackage`.
- Mainnet seeds, checkpoints, minimum chainwork and assume-valid data have been
  refreshed in the 3.1 development line.

Mempool Policy Changes
======================

- Version-3 transactions are standard subject to Topologically Restricted Until
  Confirmation (TRUC) policy: restricted unconfirmed ancestry and descendants,
  a 10,000-vB transaction limit, and a 1,000-vB limit for a transaction spending
  an unconfirmed TRUC parent. Eligible sibling replacement is supported.
- Pay To Anchor (P2A) witness outputs are recognized as standard. Relay support
  depends on the policies of the other nodes along the relay path.
- Limited package replacement is supported for eligible two-transaction clusters.
- Full replace-by-fee policy defaults to enabled (`-mempoolfullrbf=1`). The option
  is marked deprecated; disabling it does not change block consensus.
- The default `-datacarriersize` budget is 100,000 bytes. Multiple OP_RETURN
  outputs are permitted, and their complete scriptPubKey byte lengths count
  toward one aggregate budget. Other transaction-size and standardness limits
  still apply. `-datacarriersize=83` restores the smaller byte budget, not the old
  one-output restriction. `-datacarrier` and `-datacarriersize` are deprecated.

These are transaction admission, relay and mining policies, not additional
block-consensus restrictions. The P2SH CSFSVERIFY policy correction is described
above.

RPC and REST Changes
====================

- JSON-RPC 2.0 requests are supported. See [the RPC interface documentation](JSON-RPC-interface.md).
- `submitblock` matches validation results using the Bells block hash, correcting
  the 3.0.0 result-catcher mismatch that could report `inconclusive` for an accepted
  block. This corrects result reporting, not block validation rules.
- `getdeploymentinfo` exposes the `opcat` deployment and the applicable script flags.
- `dumptxoutset` writes snapshot format version 2, and `loadtxoutset` requires that
  format. Old-format dumps need to be recreated. The mainnet snapshot configuration
  specifies base height **781,902**; loading requires a snapshot matching the
  configured base block and UTXO hash.
- `warnings` in `getblockchaininfo`, `getmininginfo` and `getnetworkinfo` returns
  an array. `-deprecatedrpc=warnings` selects the legacy single-string form.
- `sendrawtransaction` reports `Transaction outputs already in utxo set` for the
  corresponding `-27` error.
- `estimatesmartfee` defaults to `economical`; `conservative` remains available.
- `scantxoutset` includes `blockhash` and `confirmations` in its unspent-output results.
- `submitpackage` accepts `maxfeerate` and `maxburnamount`. Fee-rate help text uses BEL.
- `/rest/getutxos` rejects malformed transaction IDs and output indices with
  HTTP 400 instead of silently accepting malformed input.
- `-alertnotify` handles kernel warnings, including invalid-chain warnings, and
  may run again for subsequent warning events.

Wallet and GUI Changes
======================

- Wallet RPC results expose `mempoolconflicts`. The wallet tracks these conflicts
  when determining which inputs remain spent, allowing eligible inputs to be
  reused without manually abandoning the displaced transaction.
- `fundrawtransaction`, `walletcreatefundedpsbt` and `send` accept `max_tx_weight`.
  Its default and maximum are **400,000 weight units**, the standard transaction
  limit; this is not the 4,000,000-WU block limit.
- Descriptor wallets support `gethdkeys` and `createwalletdescriptor` for listing
  HD keys and adding automatically generated descriptors.
- `sendall` can spend unconfirmed change and account for the fees needed to bump
  its unconfirmed ancestors.
- An explicit `bumpfee` fee rate is checked against the original fee and the
  mempool incremental relay requirements rather than a fixed wallet increment.
- The GUI migration menu can list legacy wallets that are not currently loaded.
  The information window displays both current and maximum mempool memory usage.

Build and Test Changes
======================

- The documented compiler minimums are GCC 11.1 or Clang 16.0. The Guix Linux
  release configuration targets glibc 2.31. See [dependencies](dependencies.md)
  and the platform build guides for build requirements.
- External signer process support uses the bundled cpp-subprocess implementation
  instead of Boost.Process.
- The separately distributed consensus verification library has been removed;
  internal consensus code remains part of the node build.
- Coverage configuration uses `LCOV_OPTS`; `--enable-lcov-branch-coverage` is removed.
- MSVC version generation preserves the release-candidate suffix.
- `test_bells` supports `-testdatadir`. Regtest enables the BIP94 timestamp check;
  this check is disabled on mainnet.
- Regression coverage includes header recovery, activation boundaries and reorgs,
  old/new block acceptance, automatic chain convergence, sigop and opcode limits,
  header-presync retarget histories, AuxPoW same-hash recovery, and the 15/16-sigop
  P2SH policy boundary. The differential tests accept an optional 3.0.0 reference
  binary; their default control uses current code with the deployment disabled.

Credits
=======

Thanks to the Bells and upstream Bitcoin Core contributors whose work is included in this release:

- Billy Markus
- Yar Sawyer
- Dim Marvel
- 0xb10c
- Alfonso Roman Zubeldia
- Andrew Toth
- AngusP
- Anthony Towns
- Antoine Poinsot
- Anton A
- Ava Chow
- Ayush Singh
- Ben Westgate
- Brandon Odiwuor
- brunoerg
- bstin
- Charlie
- Christopher Bergqvist
- Cory Fields
- crazeteam
- Daniela Brozzoni
- David Gumberg
- dergoegge
- Edil Medeiros
- Epic Curious
- Fabian Jahr
- fanquake
- furszy
- glozow
- Greg Sanders
- hanmz
- Hennadii Stepanov
- Hernan Marino
- Hodlinator
- ishaanam
- ismaelsadeeq
- Jadi
- Jon Atack
- josibake
- jrakibi
- kevkevin
- kevkevinpal
- Konstantin Akimov
- laanwj
- Larry Ruane
- Lőrinc
- Luis Schwab
- Luke Dashjr
- MarcoFalke
- marcofleon
- Marnix
- Martin Saposnic
- Martin Zumsande
- Matt Corallo
- Matthew Zipkin
- Matt Whitlock
- Max Edwards
- Michael Dietz
- Murch
- nanlour
- pablomartin4btc
- Peter Todd
- Pieter Wuille
- @RandyMcMillan
- RoboSchmied
- Roman Zeyde
- Ryan Ofsky
- Sebastian Falbesoner
- Sergi Delgado Segura
- Sjors Provoost
- spicyzboss
- StevenMia
- stickies-v
- stratospher
- Suhas Daftuar
- sunerok
- tdb3
- TheCharlatan
- umiumi
- Vasil Dimov
- virtu
- willcl-ark
