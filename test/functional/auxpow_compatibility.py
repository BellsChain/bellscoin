#!/usr/bin/env python3
# Copyright (c) 2026 The Bellscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Differential AuxPoW acceptance and same-hash recovery tests.

Use --reference-binary to compare actual 3.0.0 with current code. Otherwise
the reference is current code with opcode activation disabled. RPC delivery
exercises decoding and consensus; this is not a P2P framing test.
"""

import copy
import hashlib
import json
from pathlib import Path
import struct

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    MAX_PROTOCOL_MESSAGE_LENGTH, CAuxPow, CBlockHeader, COutPoint, CTxIn, CTxInWitness,
    CTxOut, hash256, ser_uint256, ser_uint256_vector, ser_vector,
    uint256_from_compact,
)
from test_framework.script import CScript, OP_RETURN
from test_framework.test_framework import BellscoinTestFramework
from test_framework.util import assert_equal


MARKER = b"\xfa\xbemm"
SCHEDULE = "-vbparams=opcat:0:9223372036854775807:432"


def pure_header(header):
    # The AuxPoW parent is always an 80-byte pure header, even when its
    # version has the AuxPoW bit set. CBlockHeader.serialize would recurse.
    return (struct.pack("<i", header.nVersion) + ser_uint256(header.hashPrevBlock)
            + ser_uint256(header.hashMerkleRoot) + struct.pack("<III", header.nTime, header.nBits, header.nNonce))


def proof_bytes(proof, *, hash_block=0, parent_index=0):
    # hashBlock and parent transaction index are historical wire fields.
    return (proof.coinbase_tx.serialize() + ser_uint256(hash_block)
            + ser_uint256_vector(proof.vMerkleBranch) + struct.pack("<i", parent_index)
            + ser_uint256_vector(proof.vChainMerkleBranch) + struct.pack("<i", proof.nChainIndex)
            + pure_header(proof.parent_block))


def block_bytes(block):
    return pure_header(block) + (proof_bytes(block.auxpow) if block.is_auxpow() else b"") + ser_vector(block.vtx)


def merkle_root(value, branch, index):
    if index == -1:
        return 0
    for sibling in branch:
        pair = (sibling, value) if index & 1 else (value, sibling)
        value = int.from_bytes(hash256(ser_uint256(pair[0]) + ser_uint256(pair[1])), "little")
        index >>= 1
    return value


def mine_parent(block, valid=True):
    parent = block.auxpow.parent_block
    target = uint256_from_compact(block.nBits)
    while True:
        parent.rehash()
        if (parent.scrypt256 <= target) == valid:
            return
        parent.nNonce += 1


def update_parent(block):
    proof = block.auxpow
    proof.coinbase_tx.rehash()
    proof.parent_block.hashMerkleRoot = merkle_root(proof.coinbase_tx.sha256, proof.vMerkleBranch, 0)
    mine_parent(block)


def set_commitment(block, data):
    block.auxpow.coinbase_tx.vin[0].scriptSig = CScript(data)
    update_parent(block)


def chain_proof(block, height, *, nonce=123, index=None):
    proof = block.auxpow
    proof.vChainMerkleBranch = list(range(1, height + 1))
    expected = (((nonce * 1103515245 + 12345 + 16) * 1103515245 + 12345) & ((1 << height) - 1))
    proof.nChainIndex = expected if index is None else index
    root = merkle_root(block.sha256, proof.vChainMerkleBranch, proof.nChainIndex)
    set_commitment(block, MARKER + root.to_bytes(32, "big") + struct.pack("<II", 1 << height, nonce))


class AuxpowCompatibilityTest(BellscoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--reference-binary", type=Path)
        parser.add_argument("--evidence-dir", type=Path)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.bind_to_localhost_only = False
        isolated = ["-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-discover=0"]
        reference = [] if self.options.reference_binary else ["-vbparams=opcat:-2:9223372036854775807"]
        self.extra_args = [isolated + reference, isolated + [SCHEDULE]]

    def setup_network(self):
        reference = str(self.options.reference_binary.resolve()) if self.options.reference_binary else self.options.bellsd
        self.add_nodes(2, self.extra_args, binary=[reference, self.options.bellsd])
        self.start_nodes()

    def block(self, label, version=0x00100100):
        node = self.nodes[1]
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(node.getblockcount() + 1,
                             extra_output_script=CScript([OP_RETURN, label.encode()])),
                             node.getblockheader(tip)["time"] + 1)
        block.nVersion = version if version < (1 << 31) else version - (1 << 32)
        block.rehash()
        if block.is_auxpow():
            proof = CAuxPow()
            proof.coinbase_tx.vin = [CTxIn(COutPoint(0, 0xffffffff))]
            proof.parent_block = CBlockHeader()
            proof.parent_block.nVersion = 1
            block.auxpow = proof
            set_commitment(block, MARKER + bytes.fromhex(block.hash) + struct.pack("<II", 1, 0))
        else:
            block.solve()
        return block

    def submit(self, label, block, *, raw=None):
        raw = block_bytes(block) if raw is None else raw
        digest = hashlib.sha256(raw).hexdigest()
        row = {"label": label, "hash": block.hash, "sha256": digest, "size": len(raw),
               "responses": [], "accepted": [], "invalid": []}
        self.results["blocks"].append(row)
        if self.options.evidence_dir:
            (self.options.evidence_dir / "blocks" / (digest + ".bin")).write_bytes(raw)
        for node in self.nodes:
            try:
                response = node.submitblock(raw.hex())
            except JSONRPCException as exc:
                response = exc.error
            row["responses"].append(response)
            row["accepted"].append(node.getbestblockhash() == block.hash)
            row["invalid"].append(any(tip["hash"] == block.hash and tip["status"] == "invalid" for tip in node.getchaintips()))
        return row

    def reset_case(self, block, parent):
        for node in self.nodes:
            if node.getbestblockhash() == block.hash:
                node.invalidateblock(block.hash)
            assert_equal(node.getbestblockhash(), parent)

    def acceptance(self, label, block, expected, raw=None):
        parent = self.nodes[1].getbestblockhash()
        row = self.submit(label, block, raw=raw)
        row["expected"] = [expected, expected]
        assert_equal(row["accepted"], row["expected"])
        self.reset_case(block, parent)

    def recovery(self, label, good, bad_raw, *, header_first=False, restart=False):
        parent = self.nodes[1].getbestblockhash()
        assert_equal(bad_raw[:80], pure_header(good))
        if header_first:
            for node in self.nodes:
                node.submitheader((pure_header(good) + proof_bytes(good.auxpow)).hex())
                assert_equal(node.getblockheader(good.hash)["hash"], good.hash)
        row = self.submit(label + "-bad", good, raw=bad_raw)
        row.update(expected=[False, False], header_first=header_first, restart=restart)
        assert_equal(row["accepted"], [False, False])
        assert_equal(row["invalid"], [False, False])
        if restart:
            self.restart_node(0)
            self.restart_node(1)
        row = self.submit(label + "-valid-same-hash", good)
        row["expected"] = [True, True]
        assert_equal(row["accepted"], [True, True])
        self.reset_case(good, parent)

    def matrix(self, phase):
        self.log.info("%s: child/parent versions and chain IDs", phase)
        for aux in (False, True):
            for chain_id in range(32):
                version = 0x20000004 | (chain_id << 16) | (0x100 if aux else 0)
                label = f"{phase}-child-{int(aux)}-{chain_id}"
                self.acceptance(label, self.block(label, version), chain_id == 16 if aux else chain_id in (0, 16))
        for version, expected in [(0, True), (1, True), (2, True), (3, True), (4, True),
                                  (0x10000000, True), (0x40000000, True), (0x60000000, True),
                                  (0x80000000, True), (0x00200004, False), (0x01000004, False),
                                  (0x801f0004, True), (0x80100100, True), (0x00300100, False)]:
            label = f"{phase}-version-{version:08x}"
            self.acceptance(label, self.block(label, version), expected)
        for aux in (False, True):
            for chain_id in range(32):
                label = f"{phase}-parent-{int(aux)}-{chain_id}"
                good = self.block(label)
                modified = copy.deepcopy(good)
                modified.auxpow.parent_block.nVersion = 1 | (chain_id << 16) | (0x100 if aux else 0)
                mine_parent(modified)
                if aux and chain_id == 16:
                    self.recovery(label, good, block_bytes(modified), header_first=True)
                else:
                    self.acceptance(label, modified, True)

        self.log.info("%s: valid alternative proof structures", phase)
        for height in (0, 1, 2, 30):
            label = f"{phase}-chain-depth-{height}"
            block = self.block(label)
            chain_proof(block, height)
            self.acceptance(label, block, True)
        for height in (1, 31):
            label = f"{phase}-parent-depth-{height}"
            block = self.block(label)
            block.auxpow.vMerkleBranch = list(range(1, height + 1))
            update_parent(block)
            self.acceptance(label, block, True)
        for size in (1, 32, 520):
            label = f"{phase}-parent-witness-{size}"
            block = self.block(label)
            block.auxpow.coinbase_tx.wit.vtxinwit = [CTxInWitness()]
            block.auxpow.coinbase_tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(size)]
            self.acceptance(label, block, True)
        label = phase + "-ignored-wire-fields"
        block = self.block(label)
        raw = pure_header(block) + proof_bytes(block.auxpow, hash_block=12345, parent_index=-1) + ser_vector(block.vtx)
        self.acceptance(label, block, True, raw)
        label = phase + "-rpc-trailing-proof"
        block = self.block(label, 0x20000000)
        other = self.block(label + "-aux")
        # Trailing bytes are ignored by DecodeHexBlk; they are not an AuxPoW
        # proof attached to the parsed non-AuxPoW block.
        self.acceptance(label, block, True, block_bytes(block) + proof_bytes(other.auxpow))

        self.log.info("%s: malformed proofs, first and after a valid header is known", phase)
        mutations = ["parent-pow", "parent-root", "missing-root", "missing-marker", "duplicate-marker",
                     "separated-marker", "short-trailer", "wrong-size", "wrong-index", "negative-index",
                     "chain-depth-31", "chain-sibling", "parent-sibling", "empty-parent-inputs",
                     "base-size-limit", "missing-proof", "truncated-proof", "empty-child-transactions"]
        for header_first in (False, True):
            for mutation in mutations:
                label = f"{phase}-{mutation}-header{int(header_first)}"
                good = self.block(label)
                bad = copy.deepcopy(good)
                proof = bad.auxpow
                commitment = MARKER + bytes.fromhex(good.hash) + struct.pack("<II", 1, 0)
                if mutation == "parent-pow":
                    mine_parent(bad, valid=False)
                elif mutation == "parent-root":
                    proof.parent_block.hashMerkleRoot ^= 1
                    mine_parent(bad)
                elif mutation == "missing-root":
                    set_commitment(bad, MARKER + bytes(32) + struct.pack("<II", 1, 0))
                elif mutation == "missing-marker":
                    set_commitment(bad, commitment[4:])
                elif mutation == "duplicate-marker":
                    set_commitment(bad, commitment + MARKER)
                elif mutation == "separated-marker":
                    set_commitment(bad, MARKER + b"x" + commitment[4:])
                elif mutation == "short-trailer":
                    set_commitment(bad, commitment[:-1])
                elif mutation == "wrong-size":
                    set_commitment(bad, commitment[:36] + struct.pack("<II", 2, 0))
                elif mutation == "wrong-index":
                    chain_proof(bad, 0, index=1)
                elif mutation == "negative-index":
                    chain_proof(bad, 0, index=-1)
                elif mutation == "chain-depth-31":
                    chain_proof(bad, 31)
                elif mutation == "chain-sibling":
                    chain_proof(bad, 1)
                    proof.vChainMerkleBranch[0] ^= 1
                elif mutation == "parent-sibling":
                    proof.vMerkleBranch = [1]
                    update_parent(bad)
                    proof.vMerkleBranch[0] ^= 1
                elif mutation == "empty-parent-inputs":
                    proof.coinbase_tx.vin = []
                    # Empty vout supplies a zero optional-witness flag when
                    # the parser encounters empty vin; locktime follows.
                    proof.coinbase_tx.vout = []
                    update_parent(bad)
                elif mutation == "base-size-limit":
                    proof.coinbase_tx.vout = [CTxOut(0, CScript([OP_RETURN, bytes(1_000_000)]))]
                    update_parent(bad)
                raw = block_bytes(bad)
                if mutation == "missing-proof":
                    raw = pure_header(good) + ser_vector(good.vtx)
                elif mutation == "truncated-proof":
                    raw = pure_header(good) + proof_bytes(good.auxpow)[:-1]
                elif mutation == "empty-child-transactions":
                    raw = pure_header(good) + proof_bytes(good.auxpow) + b"\x00"
                self.recovery(label, good, raw, header_first=header_first,
                              restart=header_first and mutation in ("parent-pow", "base-size-limit"))

        label = phase + "-unexpected-proof-field"
        plain = self.block(label, 0x20000000)
        aux = self.block(label + "-aux")
        self.acceptance(label, plain, False, pure_header(plain) + proof_bytes(aux.auxpow) + ser_vector(plain.vtx))
        # Decode rejection must not prevent the ordinary serialization later.
        self.acceptance(label + "-valid", plain, True)

    def known_witness_cache_case(self):
        self.log.info("Confirm the known old witness-cache defect and the existing dev fix")
        parent = self.nodes[1].getbestblockhash()
        good = self.block("known-witness-cache")
        bad = copy.deepcopy(good)
        bad.auxpow.coinbase_tx.wit.vtxinwit = [CTxInWitness()]
        bad.auxpow.coinbase_tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(3_999_000)]
        assert_equal(pure_header(bad), pure_header(good))
        assert_equal(bad.auxpow.coinbase_tx.rehash(), good.auxpow.coinbase_tx.rehash())
        assert len(block_bytes(bad)) <= MAX_PROTOCOL_MESSAGE_LENGTH
        row = self.submit("known-witness-cache-overweight", bad)
        row["expected"] = [False, False]
        assert_equal(row["accepted"], [False, False])
        assert_equal(row["invalid"], [bool(self.options.reference_binary), False])
        for i in (0, 1):
            self.restart_node(i)
        row = self.submit("known-witness-cache-original", good)
        row["expected"] = [not bool(self.options.reference_binary), True]
        assert_equal(row["accepted"], row["expected"])
        if self.options.reference_binary:
            # Recovery only for the known 3.0.0 caching defect, after recording
            # the failure. Other same-hash cases never use reconsiderblock.
            self.nodes[0].reconsiderblock(good.hash)
            self.nodes[0].submitblock(block_bytes(good).hex())
            assert_equal(self.nodes[0].getbestblockhash(), good.hash)
        self.reset_case(good, parent)

    def run_test(self):
        if self.options.evidence_dir:
            self.options.evidence_dir.mkdir(parents=True, exist_ok=False)
            (self.options.evidence_dir / "blocks").mkdir()
        self.results = {"passed": False, "reference_mode": "3.0.0" if self.options.reference_binary else "current-disabled",
                        "schedule": SCHEDULE, "binaries": [], "blocks": []}
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
            while self.nodes[1].getblockcount() < 430:
                height = self.nodes[1].getblockcount() + 1
                block = self.block(f"setup-{height}", 0x20000004 if 144 <= height < 288 else 0x20000000)
                assert_equal(block_bytes(block), block.serialize())
                assert_equal(self.submit("setup", block)["accepted"], [True, True])
            for phase in ("preactivation", "active"):
                self.matrix(phase)
                block = self.block(phase + "-common", 0x20100100)
                assert_equal(self.submit(phase + "-common", block)["accepted"], [True, True])
                info = self.nodes[1].getdeploymentinfo()["deployments"]["opcat"]["bip9"]
                assert_equal(info["status"], "locked_in" if phase == "preactivation" else "active")
                assert_equal(info["status_next"], "active")
            self.known_witness_cache_case()
            assert_equal(self.nodes[1].getblockcount(), 432)
            assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
            for node in self.nodes:
                assert_equal(node.getpeerinfo(), [])
            self.results.update(passed=True, final_tip=self.nodes[1].getbestblockhash(),
                                final_height=self.nodes[1].getblockcount())
        finally:
            if self.options.evidence_dir:
                (self.options.evidence_dir / "result.json").write_text(json.dumps(self.results, indent=2, default=str) + "\n")


if __name__ == "__main__":
    AuxpowCompatibilityTest(__file__).main()
