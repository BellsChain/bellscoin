#!/usr/bin/env python3
# Copyright (c) 2026 The Bellscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise activation reorgs and automatic old/new chain convergence.

By default the reference node runs the current binary with OP_CAT disabled.
Pass --reference-binary=/path/to/3.0.0/bellsd to test an actual old binary.
Blocks are delivered by RPC to isolated nodes; chain selection uses real work.
No invalidateblock, reconsiderblock, or preciousblock calls are used.
"""

import hashlib
import json
from pathlib import Path

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript, OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_RETURN, OP_TRUE
from test_framework.test_framework import BellscoinTestFramework
from test_framework.util import assert_equal


SCHEDULE = "-vbparams=opcat:0:9223372036854775807:432"
OPCODE_FLAGS = {"OP_CAT", "DEFAULT_CHECK_TEMPLATE_VERIFY_HASH", "INTERNALKEY", "CHECKSIGFROMSTACK"}


class OpcodeReorgTest(BellscoinTestFramework):
    def add_options(self, parser):
        parser.add_argument("--reference-binary", type=Path, help="Actual 3.0.0 bellsd; otherwise use current binary with OP_CAT disabled")
        parser.add_argument("--evidence-dir", type=Path, help="New directory for block bytes and JSON results, outside node datadirs")

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.bind_to_localhost_only = False
        isolated = ["-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0", "-discover=0"]
        reference_args = [] if self.options.reference_binary else ["-vbparams=opcat:-2:9223372036854775807"]
        self.extra_args = [isolated + reference_args, isolated + [SCHEDULE]]

    def setup_network(self):
        reference = str(self.options.reference_binary.resolve()) if self.options.reference_binary else self.options.bellsd
        self.add_nodes(2, self.extra_args, binary=[reference, self.options.bellsd])
        self.start_nodes()

    def block(self, parent, label, *, signal=False, txs=(), funding=False, auxpow=False):
        header = self.headers[parent]
        coinbase = create_coinbase(header["height"] + 1, extra_output_script=CScript([OP_RETURN, label.encode()]))
        if funding:
            # This succeeds as NOP4 before activation, but its zero template
            # hash cannot match the spending transaction after activation.
            coinbase.vout.append(CTxOut(0, CScript([bytes(32), OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_TRUE])))
            coinbase.rehash()
        block = create_block(int(parent, 16), coinbase, header["time"] + 1,
                             version=0x00100100 if auxpow else (0x20000004 if signal else 0x20000000),
                             txlist=txs, use_auxpow=auxpow)
        self.headers[block.hash] = {"height": header["height"] + 1, "time": block.nTime}
        return block

    def submit(self, block, *, targets=(0, 1)):
        raw = block.serialize()
        row = {"hash": block.hash, "height": self.headers[block.hash]["height"],
               "parent": f"{block.hashPrevBlock:064x}", "sha256": hashlib.sha256(raw).hexdigest(),
               "responses": {}, "tips": {}}
        self.results["blocks"].append(row)
        if self.options.evidence_dir:
            (self.options.evidence_dir / "blocks" / (block.hash + ".bin")).write_bytes(raw)
        for index in targets:
            # 3.0.0 submitblock's state catcher uses the PoW hash instead of
            # the block hash. Assert actual chain tips separately below.
            row["responses"][index] = self.nodes[index].submitblock(raw.hex())
        row["tips"] = [node.getbestblockhash() for node in self.nodes]
        return row["responses"]

    def expect_tips(self, reference, dev):
        assert_equal(self.nodes[0].getbestblockhash(), reference)
        assert_equal(self.nodes[1].getbestblockhash(), dev)

    def state(self, label, tip, status, *, next_status=None):
        self.expect_tips(tip, tip)
        info = self.nodes[1].getdeploymentinfo()
        deployment = info["deployments"]["opcat"]
        assert_equal(deployment["bip9"]["status"], status)
        if next_status is not None:
            assert_equal(deployment["bip9"]["status_next"], next_status)
        flags = set(info["script_flags"])
        assert_equal(flags & OPCODE_FLAGS, OPCODE_FLAGS if status == "active" else set())
        chains = [node.getblockchaininfo() for node in self.nodes]
        assert_equal(chains[0]["chainwork"], chains[1]["chainwork"])
        self.results["checkpoints"].append({"label": label, "tip": tip, "height": info["height"],
                                            "chainwork": chains[0]["chainwork"], "deployment": deployment,
                                            "script_flags": info["script_flags"]})
        self.log.info("%s: height %d, state %s, shared tip %s", label, info["height"], status, tip)

    def work(self, block_hash):
        return int(self.nodes[0].getblockheader(block_hash)["chainwork"], 16)

    def run_test(self):
        if self.options.evidence_dir:
            self.options.evidence_dir.mkdir(parents=True, exist_ok=False)
            (self.options.evidence_dir / "blocks").mkdir()
        self.results = {"passed": False, "reference_mode": "3.0.0" if self.options.reference_binary else "current-disabled",
                        "schedule": SCHEDULE, "binaries": [], "blocks": [], "checkpoints": []}
        try:
            for node in self.nodes:
                binary = Path(node.binary).resolve()
                digest = hashlib.sha256()
                with binary.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1 << 20), b""):
                        digest.update(chunk)
                network = node.getnetworkinfo()
                self.results["binaries"].append({"path": str(binary), "sha256": digest.hexdigest(),
                                                "version": network["version"], "subversion": network["subversion"]})
                assert_equal(node.getpeerinfo(), [])
            if self.options.reference_binary:
                assert_equal(self.nodes[0].getnetworkinfo()["version"], 30000)
            self.run_scenarios()
            self.results["passed"] = True
        finally:
            if self.options.evidence_dir:
                (self.options.evidence_dir / "result.json").write_text(json.dumps(self.results, indent=2, default=str) + "\n")

    def run_scenarios(self):
        reference, dev = self.nodes
        genesis = dev.getblockhash(0)
        assert_equal(reference.getblockhash(0), genesis)
        self.headers = {genesis: dev.getblockheader(genesis)}
        funding = self.block(genesis, "funding", funding=True)
        self.submit(funding)
        self.expect_tips(funding.hash, funding.hash)
        outpoint = COutPoint(funding.vtx[0].sha256, 2)
        funding_txid = funding.vtx[0].hash
        spend = CTransaction()
        spend.vin = [CTxIn(outpoint)]
        spend.vout = [CTxOut(0, CScript([OP_TRUE]))]
        spend.rehash()
        parent = funding.hash
        for height in range(2, 144):
            block = self.block(parent, f"common-{height}")
            self.submit(block)
            self.expect_tips(block.hash, block.hash)
            parent = block.hash
        fork = parent
        self.state("common fork", fork, "defined", next_status="started")

        self.log.info("Branch A signals, locks in and activates")
        for height in range(144, 436):
            block = self.block(parent, f"A-{height}", signal=height < 288)
            self.submit(block)
            self.expect_tips(block.hash, block.hash)
            parent = block.hash
            if height == 287:
                self.state("A locks in next", parent, "started", next_status="locked_in")
            if height == 431:
                self.state("A activates next", parent, "locked_in", next_status="active")
        a_tip = parent
        self.state("A active", a_tip, "active")
        probe = self.block(a_tip, "active-probe", txs=[spend], auxpow=True)
        assert_equal(self.submit(probe, targets=(1,))[1], "block-validation-failed")
        self.expect_tips(a_tip, a_tip)

        self.log.info("A heavier non-signaling branch undoes activation and accepts the same CTV spend")
        parent = fork
        for height in range(144, 437):
            block = self.block(parent, f"B-{height}", txs=[spend] if height == 432 else [])
            self.submit(block)
            parent = block.hash
            if height <= 435:
                self.expect_tips(a_tip, a_tip)
                assert self.work(parent) <= self.work(a_tip)
            else:
                assert self.work(parent) > self.work(a_tip)
        b_tip = parent
        self.state("B wins; activation undone", b_tip, "started")
        for node in self.nodes:
            assert_equal(node.gettxout(funding_txid, 2, False), None)
        self.restart_node(1)
        self.state("B after dev restart", b_tip, "started")

        self.log.info("Extending A past B restores activation and undoes B's CTV spend")
        parent = a_tip
        for height in (436, 437):
            block = self.block(parent, f"A-{height}")
            self.submit(block)
            parent = block.hash
            if height == 436:
                assert_equal(self.work(parent), self.work(b_tip))
                self.expect_tips(b_tip, b_tip)
            else:
                assert self.work(parent) > self.work(b_tip)
        a_tip = parent
        self.state("A wins again; activation restored", a_tip, "active")
        for node in self.nodes:
            assert node.gettxout(funding_txid, 2, False) is not None

        self.log.info("Old node follows three blocks on a branch violating activated CTV")
        bad = self.block(a_tip, "old-only-438", txs=[spend], auxpow=True)
        assert_equal(self.submit(bad)[1], "block-validation-failed")
        self.expect_tips(bad.hash, a_tip)
        invalid_tip = bad.hash
        for height in (439, 440):
            block = self.block(invalid_tip, f"old-only-{height}")
            responses = self.submit(block)
            assert responses[1] in ("bad-prevblk", "prev-blk-not-found"), responses
            invalid_tip = block.hash
            self.expect_tips(invalid_tip, a_tip)
        assert self.work(invalid_tip) > self.work(a_tip)
        self.results["divergence"] = {"reference_tip": invalid_tip, "dev_tip": a_tip,
                                      "reference_chainwork": reference.getblockchaininfo()["chainwork"],
                                      "dev_chainwork": dev.getblockchaininfo()["chainwork"]}
        self.restart_node(0)
        self.restart_node(1)
        self.expect_tips(invalid_tip, a_tip)
        assert_equal(dev.submitblock(bad.serialize().hex()), "duplicate-invalid")

        self.log.info("The enforcing branch overtakes the old-only branch without administrative RPCs")
        parent = a_tip
        for height in range(438, 442):
            block = self.block(parent, f"valid-{height}", auxpow=True)
            self.submit(block)
            parent = block.hash
            if height <= 440:
                self.expect_tips(invalid_tip, parent)
                assert self.work(parent) <= self.work(invalid_tip)
            else:
                assert self.work(parent) > self.work(invalid_tip)
        self.state("automatic convergence", parent, "active")
        assert any(tip["hash"] == invalid_tip and tip["status"] == "valid-fork" for tip in reference.getchaintips())
        assert any(tip["hash"] == bad.hash and tip["status"] == "invalid" for tip in dev.getchaintips())
        for node in self.nodes:
            assert node.gettxout(funding_txid, 2, False) is not None
        self.restart_node(0)
        self.restart_node(1)
        self.state("convergence persists after restart", parent, "active")
        assert_equal(dev.submitblock(bad.serialize().hex()), "duplicate-invalid")
        final = self.block(parent, "shared-progress", auxpow=True)
        self.submit(final)
        self.state("shared progress", final.hash, "active")
        for node in self.nodes:
            assert_equal(node.getpeerinfo(), [])


if __name__ == "__main__":
    OpcodeReorgTest(__file__).main()
