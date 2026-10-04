#!/usr/bin/env python3
# Copyright (c) 2026 The Bellscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compare opcode boundary blocks before and after activation with old rules.

Use --reference-binary for actual 3.0.0; otherwise the reference runs current
code with OP_CAT disabled. Individual cases use invalidateblock for isolation.
Automatic convergence without invalidation is covered by feature_opcat_reorg.py.
"""

import hashlib
import json
from pathlib import Path

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.key import ORDER, TaggedHash, compute_xonly_pubkey, secp256k1, sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, sha256
from test_framework.script import (
    CScript, OP_0, OP_CAT, OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_ENDIF,
    OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_IF, OP_INTERNALKEY, OP_NOP5,
    OP_RETURN, OP_TRUE, hash160, taproot_construct,
)
from test_framework.test_framework import BellscoinTestFramework
from test_framework.util import assert_equal


STACK_ERROR = "Stack size limit exceeded"
PUSH_ERROR = "Push value size limit exceeded"
UNDERFLOW = "Operation not valid with the current stack size"
SIG_SIZE = "Invalid Schnorr signature size"
SIG_ERROR = "Invalid Schnorr signature"
VERIFY_ERROR = "Script failed an OP_CHECKSIGVERIFY operation"
BUDGET_ERROR = "Too much signature validation relative to witness weight"


def sign_message(secret, message):
    """BIP340 signing with arbitrary message length for CSFS test vectors."""
    scalar = int.from_bytes(secret, "big")
    point = scalar * secp256k1.G
    if not point.y.is_even():
        scalar = ORDER - scalar
    masked = (scalar ^ int.from_bytes(TaggedHash("BIP0340/aux", bytes(32)), "big")).to_bytes(32, "big")
    nonce = int.from_bytes(TaggedHash("BIP0340/nonce", masked + point.to_bytes_xonly() + message), "big") % ORDER
    assert nonce
    r = nonce * secp256k1.G
    nonce = nonce if r.y.is_even() else ORDER - nonce
    challenge = int.from_bytes(TaggedHash("BIP0340/challenge", r.to_bytes_xonly() + point.to_bytes_xonly() + message), "big") % ORDER
    return r.to_bytes_xonly() + ((nonce + challenge * scalar) % ORDER).to_bytes(32, "big")


class OpcodeLimitsTest(BellscoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--reference-binary", type=Path)
        parser.add_argument("--evidence-dir", type=Path)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.bind_to_localhost_only = False
        # Serial script checking preserves the precise consensus error in RPC.
        isolated = ["-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-discover=0", "-par=1"]
        reference = [] if self.options.reference_binary else ["-vbparams=opcat:-2:9223372036854775807"]
        self.extra_args = [isolated + reference, isolated + ["-vbparams=opcat:0:9223372036854775807:432"]]

    def setup_network(self):
        reference = str(self.options.reference_binary.resolve()) if self.options.reference_binary else self.options.bellsd
        self.add_nodes(2, self.extra_args, binary=[reference, self.options.bellsd])
        self.start_nodes()

    def add_coin(self, kind, script):
        script = CScript(script)
        payload = script
        if kind == "tap":
            payload = taproot_construct(self.pubkey, [("test", script)])
            spk = payload.scriptPubKey
        elif kind == "p2sh":
            spk = CScript([OP_HASH160, hash160(script), OP_EQUAL])
        else:
            assert_equal(kind, "p2wsh")
            spk = CScript([OP_0, sha256(script)])
        self.coins.append((kind, payload))
        self.funding.vout.append(CTxOut(0, spk))
        return len(self.coins) - 1

    def spend(self, indices, inputs=None):
        tx = CTransaction()
        tx.vout = [CTxOut(0, CScript([OP_TRUE]))]
        for index in indices:
            kind, payload = self.coins[index]
            stack = list(inputs or [])
            script_sig = b""
            witness = CTxInWitness()
            if kind == "p2sh":
                script_sig = CScript(stack + [payload])
            elif kind == "p2wsh":
                witness.scriptWitness.stack = stack + [bytes(payload)]
            else:
                leaf = payload.leaves["test"]
                control = bytes([leaf.version + payload.negflag]) + payload.internal_pubkey + leaf.merklebranch
                witness.scriptWitness.stack = stack + [bytes(leaf.script), control]
            tx.vin.append(CTxIn(COutPoint(self.funding.sha256, index + 1), script_sig))
            tx.wit.vtxinwit.append(witness)
        tx.rehash()
        return tx

    def add_case(self, name, kind, script, inputs=(), *, old_error=None, active_error=None):
        index = self.add_coin(kind, script)
        self.vectors.append({"name": name, "indices": [index], "inputs": list(inputs),
                             "old_error": old_error, "active_error": active_error})
        return self.vectors[-1]

    def build_vectors(self):
        secret = (1).to_bytes(32, "big")
        self.pubkey = compute_xonly_pubkey(secret)[0]
        message = b"m" * 32
        signature = sign_message(secret, message)
        assert_equal(signature, sign_schnorr(secret, message))
        cleanup = [OP_DROP, OP_DROP, OP_DROP, OP_TRUE]
        for length in (0, 1, 32, 520):
            msg = b"m" * length
            sig = sign_message(secret, msg)
            # Check all three retained operands, including their contents.
            script = [OP_NOP5, self.pubkey, OP_EQUALVERIFY, msg, OP_EQUALVERIFY, sig, OP_EQUAL]
            self.add_case(f"csfsv_message_{length}", "tap", script, [sig, msg, self.pubkey])
        for length in (0, 63, 65):
            sig = signature[:length] if length < 64 else signature + b"\x00"
            error = VERIFY_ERROR if length == 0 else SIG_SIZE
            self.add_case(f"csfsv_signature_{length}", "tap", [OP_NOP5] + cleanup,
                          [sig, message, self.pubkey], active_error=error)
        bad_signature = signature[:-1] + bytes([signature[-1] ^ 1])
        self.add_case("csfsv_bad_signature", "tap", [OP_NOP5] + cleanup,
                      [bad_signature, message, self.pubkey], active_error=SIG_ERROR)
        self.add_case("csfsv_wrong_message", "tap", [OP_NOP5] + cleanup,
                      [signature, b"x" * 32, self.pubkey], active_error=SIG_ERROR)
        self.add_case("csfsv_empty_pubkey", "tap", [OP_NOP5] + cleanup,
                      [signature, message, b""], active_error="Public key is neither compressed or uncompressed")
        for length in (1, 31, 33, 520):
            self.add_case(f"csfsv_future_pubkey_{length}", "tap", [OP_NOP5] + cleanup,
                          [b"\x01", message, b"p" * length])
        self.add_case("csfsv_future_key_empty_signature", "tap", [OP_NOP5] + cleanup,
                      [b"", message, b"p"], active_error=VERIFY_ERROR)
        for count in range(3):
            self.add_case(f"csfsv_underflow_{count}", "tap", [OP_NOP5] + [OP_DROP] * count + [OP_TRUE],
                          [b"x"] * count, active_error=UNDERFLOW)
        self.add_case("csfsv_message_521", "tap", [OP_NOP5] + cleanup,
                      [signature, b"m" * 521, self.pubkey], old_error=PUSH_ERROR, active_error=PUSH_ERROR)
        self.add_case("csfsv_unexecuted_1000", "tap", [OP_0, OP_IF] + [OP_NOP5] * 1000 + [OP_ENDIF, OP_TRUE])

        for key_type, sig, msg, pub in [("known", signature, message, self.pubkey), ("future", b"s", b"", b"p")]:
            # Ten executed checks consume 500 units. Change only witness padding
            # to test exactly zero remaining budget and one unit below zero.
            script = [OP_DROP] + [OP_NOP5] * 10 + cleanup
            vector = self.add_case(f"csfsv_budget_{key_type}_exact", "tap", script)
            for padding in range(521):
                args = [sig, msg, pub, bytes(padding)]
                tx = self.spend(vector["indices"], args)
                if len(tx.wit.vtxinwit[0].serialize()) + 50 == 500:
                    vector["inputs"] = args
                    vector["validation_budget"] = 500
                    break
            else:
                raise AssertionError("Unable to construct exact tapscript validation budget")
            below = self.add_case(f"csfsv_budget_{key_type}_below", "tap", script,
                                  [sig, msg, pub, bytes(padding - 1)], active_error=BUDGET_ERROR)
            assert_equal(len(self.spend(below["indices"], below["inputs"]).wit.vtxinwit[0].serialize()) + 50, 499)
            below["validation_budget"] = 499

        for count in (1000, 1001):
            inputs = [b""] * (count - 3) + [signature, message, self.pubkey]
            error = STACK_ERROR if count > 1000 else None
            self.add_case(f"csfsv_stack_{count}", "tap", [OP_NOP5] + [OP_DROP] * count + [OP_TRUE], inputs,
                          old_error=error, active_error=error)

        for size in (519, 520, 521):
            self.add_case(f"cat_result_{size}", "tap", [OP_CAT, OP_DROP, OP_TRUE],
                          [b"a" * 260, b"b" * (size - 260)], active_error=PUSH_ERROR if size > 520 else None)
        for count in (0, 1):
            self.add_case(f"cat_underflow_{count}", "tap", [OP_CAT, OP_DROP, OP_TRUE],
                          [b"a"] * count, active_error=UNDERFLOW)
        for count in (1000, 1001):
            # Old OP_SUCCESS bypasses the initial-stack limit; active CAT does not.
            self.add_case(f"cat_initial_stack_{count}", "tap", [OP_CAT] + [OP_DROP] * (count - 1) + [OP_TRUE],
                          [b""] * count, active_error=STACK_ERROR if count > 1000 else None)
        self.add_case("cat_witness_v0", "p2wsh", [OP_CAT, OP_DROP, OP_TRUE], [b"a", b"b"],
                      old_error="Attempted to use a disabled opcode", active_error="Attempted to use a disabled opcode")
        self.add_case("internalkey_witness_v0", "p2wsh", [OP_INTERNALKEY, OP_DROP, OP_TRUE],
                      old_error="Opcode missing or not understood", active_error="Opcode missing or not understood")

        for size in (0, 31, 32, 33, 520, 521):
            error = PUSH_ERROR if size > 520 else None
            self.add_case(f"ctv_argument_{size}", "tap", [OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_TRUE], [bytes(size)],
                          old_error=error, active_error="Script failed an OP_CHECKTEMPLATEVERIFY operation" if size == 32 else error)
        # An empty stack followed by TRUE passes old NOP4 semantics. This
        # specifically tests CTV underflow, not an empty final stack failure.
        self.add_case("ctv_empty_stack", "tap", [OP_CHECKTEMPLATEVERIFY, OP_TRUE], active_error=UNDERFLOW)

        # Per-script opcode counts stay <= 201; every NOP5 is unexecuted.
        def nops(count):
            return [OP_0, OP_IF] + [OP_NOP5] * count + [OP_ENDIF, OP_TRUE]

        for kind, copies, tail in [("p2sh", 100, 100), ("p2wsh", 402, 2)]:
            indices = [self.add_coin(kind, nops(199)) for _ in range(copies)]
            for extra in (0, 1):
                cost = (copies * 199 + tail + extra) * (4 if kind == "p2sh" else 1)
                assert_equal(cost, 80000 + extra * (4 if kind == "p2sh" else 1))
                self.vectors.append({"name": f"{kind}_sigops_{cost}", "indices": indices + [self.add_coin(kind, nops(tail + extra))],
                                     "inputs": [], "old_error": None, "active_error": "bad-blk-sigops" if extra else None,
                                     "active_sigop_cost": cost})

    def block(self, label, txs=(), coinbase=None):
        node = self.nodes[1]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        if coinbase is None:
            coinbase = create_coinbase(height, extra_output_script=CScript([OP_RETURN, label.encode()]))
        block = create_block(int(tip, 16), coinbase, node.getblockheader(tip)["time"] + 1,
                             version=0x20000004 if 144 <= height < 288 else 0x20000000, txlist=txs)
        if any(not tx.wit.is_null() for tx in txs):
            add_witness_commitment(block)
            block.solve()
        return block

    def deliver(self, block, label):
        raw = block.serialize()
        row = {"label": label, "hash": block.hash, "sha256": hashlib.sha256(raw).hexdigest(),
               "height": self.nodes[1].getblockcount() + 1, "responses": [], "accepted": []}
        self.results["blocks"].append(row)
        if self.options.evidence_dir:
            (self.options.evidence_dir / "blocks" / (block.hash + ".bin")).write_bytes(raw)
        for node in self.nodes:
            row["responses"].append(node.submitblock(raw.hex()))
            row["accepted"].append(node.getbestblockhash() == block.hash)
        return row

    def check_case(self, vector, active):
        phase = "active" if active else "preactivation"
        parent = self.nodes[1].getbestblockhash()
        assert_equal(self.nodes[0].getbestblockhash(), parent)
        tx = self.spend(vector["indices"], vector["inputs"])
        label = phase + "-" + vector["name"]
        row = self.deliver(self.block(label, [tx]), label)
        expected_errors = [vector["old_error"], vector["active_error"] if active else vector["old_error"]]
        row["expected_errors"] = expected_errors
        for field in ("validation_budget", "active_sigop_cost"):
            if field in vector:
                row[field] = vector[field]
        row["pass"] = row["accepted"] == [error is None for error in expected_errors]
        assert row["pass"], row
        if expected_errors[1]:
            assert expected_errors[1] in row["responses"][1], row
        for index, node in enumerate(self.nodes):
            if row["accepted"][index]:
                node.invalidateblock(row["hash"])
            else:
                assert any(tip["hash"] == row["hash"] and tip["status"] == "invalid" for tip in node.getchaintips()), row
            assert_equal(node.getbestblockhash(), parent)
        self.log.info("%s: reference/dev accepted = %s", label, row["accepted"])

    def run_test(self):
        if self.options.evidence_dir:
            self.options.evidence_dir.mkdir(parents=True, exist_ok=False)
            (self.options.evidence_dir / "blocks").mkdir()
        self.results = {"passed": False, "reference_mode": "3.0.0" if self.options.reference_binary else "current-disabled",
                        "binaries": [], "blocks": []}
        try:
            for node in self.nodes:
                digest = hashlib.sha256()
                with Path(node.binary).open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1 << 20), b""):
                        digest.update(chunk)
                self.results["binaries"].append({"path": node.binary, "sha256": digest.hexdigest(),
                                                "version": node.getnetworkinfo()["version"]})
                assert_equal(node.getpeerinfo(), [])
            if self.options.reference_binary:
                assert_equal(self.nodes[0].getnetworkinfo()["version"], 30000)
            self.coins, self.vectors = [], []
            self.funding = create_coinbase(1)
            self.build_vectors()
            self.funding.rehash()
            assert_equal(self.deliver(self.block("funding", coinbase=self.funding), "funding")["accepted"], [True, True])
            while self.nodes[1].getblockcount() < 430:
                assert_equal(self.deliver(self.block("setup"), "setup")["accepted"], [True, True])
            for vector in self.vectors:
                self.check_case(vector, active=False)
            assert_equal(self.deliver(self.block("last-preactivation"), "last-preactivation")["accepted"], [True, True])
            assert_equal(self.nodes[1].getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "active")
            for vector in self.vectors:
                self.check_case(vector, active=True)
            final = self.block("active-common")
            assert_equal(self.deliver(final, "active-common")["accepted"], [True, True])
            assert_equal(self.nodes[1].getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status"], "active")
            self.results.update(passed=True, vector_count=len(self.vectors), comparison_cases=2 * len(self.vectors),
                                final_height=self.nodes[1].getblockcount(), final_tip=final.hash)
        finally:
            if self.options.evidence_dir:
                (self.options.evidence_dir / "result.json").write_text(json.dumps(self.results, indent=2, default=str) + "\n")


if __name__ == "__main__":
    OpcodeLimitsTest(__file__).main()
