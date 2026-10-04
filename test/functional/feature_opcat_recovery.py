#!/usr/bin/env python3
# Copyright (c) 2026 The Bellscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test legacy compatibility, failed-block recovery, and coordinated activation."""

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript, OP_CHECKSIG, OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_NOP5, OP_RETURN, OP_TRUE
from test_framework.test_framework import BellscoinTestFramework
from test_framework.util import assert_equal


DISABLED = ["-vbparams=opcat:-2:9223372036854775807"]
SCHEDULED = ["-vbparams=opcat:0:9223372036854775807:576"]
# Artificial regtest schedule, not proposed mainnet activation parameters.
FUTURE_START = 2_000_000_000
RECOVERY_THEN_ACTIVATION = [f"-vbparams=opcat:{FUTURE_START}:9223372036854775807:720"]


class OpcodeRecoveryTest(BellscoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 4
        # Old bit-2 votes before the new start must not cause early lock-in.
        self.extra_args = [DISABLED, [], SCHEDULED, RECOVERY_THEN_ACTIVATION + ["-blockversion=536870916"]]

    def setup_network(self):
        self.setup_nodes()

    def mine(self, node, count):
        return self.generatetoaddress(node, count, node.get_deterministic_priv_key().address, sync_fun=self.no_op)

    def block(self, node, *, version=0x20000000, extra_script=None, use_auxpow=False, txs=None):
        tip = node.getbestblockhash()
        return create_block(
            int(tip, 16),
            create_coinbase(node.getblockcount() + 1, extra_output_script=extra_script),
            node.getblockheader(tip)["time"] + 1,
            version=version,
            use_auxpow=use_auxpow,
            txlist=txs,
        )

    def run_test(self):
        recovery, active, scheduled, no_support = self.nodes
        large_nop5 = CScript([OP_RETURN] + [OP_NOP5] * 20001)
        large_checksig = CScript([OP_RETURN] + [OP_CHECKSIG] * 20001)

        self.log.info("Both rule sets accept the same ordinary history")
        self.mine(recovery, 40)
        self.connect_nodes(0, 1)
        self.sync_blocks([recovery, active])
        self.disconnect_nodes(0, 1)

        self.log.info("Unexecuted NOP5 output splits old and upgraded sigop rules")
        split = self.block(recovery, extra_script=large_nop5)
        assert_equal(recovery.submitblock(split.serialize().hex()), None)
        assert_equal(active.submitblock(split.serialize().hex()), "bad-blk-sigops")
        self.mine(recovery, 3)
        self.mine(active, 1)
        assert recovery.getblockchaininfo()["chainwork"] > active.getblockchaininfo()["chainwork"]
        slow_tip = active.getbestblockhash()

        self.log.info("Changing rules alone does not clear persisted invalid flags")
        self.restart_node(1, extra_args=RECOVERY_THEN_ACTIVATION)
        assert_equal(active.submitblock(split.serialize().hex()), "duplicate-invalid")
        assert_equal(active.getbestblockhash(), slow_tip)

        self.log.info("Reconsider the identified block and follow the valid higher-work branch")
        active.reconsiderblock(split.hash)
        self.connect_nodes(0, 1)
        self.sync_blocks([recovery, active])
        assert_equal(active.getbestblockhash(), recovery.getbestblockhash())
        assert_equal(active.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status"], "defined")

        self.log.info("Recovery still enforces the original sigop limit")
        bad = self.block(recovery, extra_script=large_checksig)
        assert_equal(recovery.submitblock(bad.serialize().hex()), "bad-blk-sigops")

        self.log.info("Preactivation rules accept historical base version 3")
        old_version = self.block(recovery, version=3)
        assert_equal(recovery.submitblock(old_version.serialize().hex()), None)
        self.sync_blocks([recovery, active])

        self.log.info("Accept the base-zero AuxPoW version that triggered the mainnet split at 1255678")
        base_zero = self.block(recovery, version=0x00100100, use_auxpow=True)
        assert_equal(base_zero.nVersion, 0x00100100)
        assert_equal(recovery.submitblock(base_zero.serialize().hex()), None)
        self.sync_blocks([recovery, active])

        self.log.info("The recovering binary keeps activation pending until the future MTP start")
        self.mine(active, 143 - active.getblockcount())
        self.sync_blocks([recovery, active])
        assert_equal(active.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "defined")
        assert_equal(active.getblockheader(active.getbestblockhash())["version"] & (1 << 2), 0)

        self.log.info("The same recovering node starts fresh signaling, then locks in")
        recovery.setmocktime(FUTURE_START + 100)
        active.setmocktime(FUTURE_START + 100)
        self.mine(active, 144)
        assert_equal(active.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "started")
        self.mine(active, 144)
        assert_equal(active.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "locked_in")
        self.mine(active, 144)
        assert_equal(active.getblockcount(), 575)
        assert_equal(active.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "locked_in")
        self.mine(active, 143)
        last_recovery_rules = self.block(active, extra_script=large_nop5)
        assert_equal(active.submitblock(last_recovery_rules.serialize().hex()), None)
        assert_equal(active.getblockcount(), 719)
        assert_equal(active.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "active")

        self.log.info("Activation follows recovery without another restart, while the legacy node follows valid blocks")
        bad = self.block(active, extra_script=large_nop5)
        assert_equal(active.submitblock(bad.serialize().hex()), "bad-blk-sigops")
        # The legacy node may receive and accept the rejected test block. Mine
        # two enforcing-valid blocks so that branch has strictly greater work.
        self.mine(active, 2)
        self.sync_blocks([recovery, active])
        assert_equal(active.getblockcount(), 721)
        assert_equal(active.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status"], "active")
        assert_equal(active.getblockheader(active.getbestblockhash())["version"] & (1 << 2), 0)
        for flag in ["OP_CAT", "DEFAULT_CHECK_TEMPLATE_VERIFY_HASH", "INTERNALKEY", "CHECKSIGFROMSTACK"]:
            assert flag in active.getdeploymentinfo()["script_flags"]

        self.log.info("BIP9 requires signaling, lock-in, and the minimum-height boundary")
        # A mismatched CTV template is a NOP before activation and must fail
        # afterwards, even in a block without the versionbits header marker.
        ctv_script = CScript([bytes(32), OP_CHECKTEMPLATEVERIFY, OP_DROP, OP_TRUE])
        ctv_spends = []
        for _ in range(2):
            funding = self.block(scheduled, extra_script=ctv_script)
            assert_equal(scheduled.submitblock(funding.serialize().hex()), None)
            spend = CTransaction()
            spend.vin = [CTxIn(COutPoint(funding.vtx[0].sha256, 1))]
            spend.vout = [CTxOut(0, CScript([OP_TRUE]))]
            spend.rehash()
            ctv_spends.append(spend)
        self.mine(scheduled, 140)
        old_version = self.block(scheduled, version=3, extra_script=large_nop5)
        assert_equal(scheduled.submitblock(old_version.serialize().hex()), None)
        assert_equal(scheduled.getblockcount(), 143)
        assert_equal(scheduled.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "started")
        self.mine(scheduled, 144)
        assert_equal(scheduled.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "locked_in")
        self.mine(scheduled, 144)
        assert_equal(scheduled.getblockcount(), 431)
        assert_equal(scheduled.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "locked_in")
        self.mine(scheduled, 143)
        last_old = self.block(scheduled, version=3, extra_script=large_nop5, txs=[ctv_spends[0]])
        assert_equal(scheduled.submitblock(last_old.serialize().hex()), None)
        assert_equal(scheduled.getblockcount(), 575)
        assert_equal(scheduled.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "active")

        self.log.info("The exact activation block enforces opcode rules for every header format")
        header_versions = [(3, False), (4, False), (0x40000000, False),
                           (0x00100100, True), (0x00100104, True), (0x20100100, True)]
        for version, auxpow in header_versions:
            bad = self.block(scheduled, version=version, use_auxpow=auxpow, extra_script=large_nop5)
            assert_equal(scheduled.submitblock(bad.serialize().hex()), "bad-blk-sigops")
            bad = self.block(scheduled, version=version, use_auxpow=auxpow, txs=[ctv_spends[1]])
            assert_equal(scheduled.submitblock(bad.serialize().hex()), "block-validation-failed")
        base_zero = self.block(scheduled, version=0x00100100, use_auxpow=True)
        assert_equal(base_zero.nVersion, 0x00100100)
        assert_equal(scheduled.submitblock(base_zero.serialize().hex()), None)
        assert_equal(scheduled.getblockcount(), 576)
        assert_equal(scheduled.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status"], "active")
        for flag in ["OP_CAT", "DEFAULT_CHECK_TEMPLATE_VERIFY_HASH", "INTERNALKEY", "CHECKSIGFROMSTACK"]:
            assert flag in scheduled.getdeploymentinfo()["script_flags"]

        self.log.info("Reorg across activation restores the older rules at the earlier height")
        boundary = scheduled.getbestblockhash()
        scheduled.invalidateblock(boundary)
        scheduled.invalidateblock(last_old.hash)
        assert_equal(scheduled.getblockcount(), 574)
        alternate = self.block(scheduled, version=3, extra_script=large_nop5, txs=[ctv_spends[1]])
        alternate.nTime += 1
        alternate.solve()
        assert_equal(scheduled.submitblock(alternate.serialize().hex()), None)
        assert_equal(scheduled.getblockcount(), 575)
        bad = self.block(scheduled, version=0x00100100, use_auxpow=True, extra_script=large_nop5)
        assert_equal(scheduled.submitblock(bad.serialize().hex()), "bad-blk-sigops")

        self.log.info("All previously valid header formats remain valid after activation and restart")
        for version, auxpow in header_versions:
            good = self.block(scheduled, version=version, use_auxpow=auxpow)
            assert_equal(scheduled.submitblock(good.serialize().hex()), None)
        active_tip = scheduled.getbestblockhash()
        self.restart_node(2, extra_args=SCHEDULED)
        assert_equal(scheduled.getbestblockhash(), active_tip)
        assert_equal(scheduled.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status"], "active")
        bad = self.block(scheduled, version=0x00100100, use_auxpow=True, txs=[ctv_spends[0]])
        assert_equal(scheduled.submitblock(bad.serialize().hex()), "block-validation-failed")
        good = self.block(scheduled, version=0x00100100, use_auxpow=True)
        assert_equal(scheduled.submitblock(good.serialize().hex()), None)

        self.log.info("Historical bit-2 votes before the future start cannot lock in activation")
        self.mine(no_support, 287)
        assert_equal(no_support.getblockheader(no_support.getbestblockhash())["version"] & (1 << 2), 1 << 2)
        assert_equal(no_support.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "defined")
        no_support.setmocktime(FUTURE_START + 100)
        self.mine(no_support, 144)
        assert_equal(no_support.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "started")

        self.log.info("Only votes in the new STARTED period count; CTRL-style headers are non-votes")
        self.restart_node(3, extra_args=RECOVERY_THEN_ACTIVATION + ["-blockversion=536870912", f"-mocktime={FUTURE_START + 100}"])
        no_support.setmocktime(FUTURE_START + 100)
        self.mine(no_support, 144)
        deployment = no_support.getdeploymentinfo()["deployments"]["opcat"]["bip9"]
        assert_equal(deployment["status_next"], "started")
        assert_equal(deployment["statistics"]["count"], 0)
        # Setting bit 2 without the versionbits marker is still not a vote.
        for version in [0x00100100, 0x00100104]:
            ctrl = self.block(no_support, version=version, use_auxpow=True)
            assert_equal(ctrl.nVersion, version)
            assert_equal(no_support.submitblock(ctrl.serialize().hex()), None)
        self.mine(no_support, 142)
        deployment = no_support.getdeploymentinfo()["deployments"]["opcat"]["bip9"]
        assert_equal(deployment["status_next"], "started")
        assert_equal(deployment["statistics"]["count"], 0)

        self.log.info("An unsuccessful attempt expires without forced activation")
        self.restart_node(3, extra_args=[f"-vbparams=opcat:{FUTURE_START}:{FUTURE_START + 1}:720", f"-mocktime={FUTURE_START + 100}"])
        no_support.setmocktime(FUTURE_START + 100)
        assert_equal(no_support.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status"], "failed")
        self.mine(no_support, 144)
        assert_equal(no_support.getdeploymentinfo()["deployments"]["opcat"]["bip9"]["status_next"], "failed")


if __name__ == "__main__":
    OpcodeRecoveryTest(__file__).main()
