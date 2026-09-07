"""
blockchain_ledger.py
====================
Tamper-evident cryptographic hash-chain ledger for TraceVault.

Every investigation action is recorded as an immutable block:
  block_hash = SHA-256(block_index | prev_hash | timestamp | case_id
                       | action | actor | data_hash)

Optional: anchor the chain head to Polygon Amoy testnet via web3.py.
Set ENABLE_BLOCKCHAIN_ANCHORING=true in .env to activate.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.blockchain import BlockchainLedger


# ---------------------------------------------------------------------------
# Genesis block constant
# ---------------------------------------------------------------------------

GENESIS_DATA: dict = {
    "message": "TraceVault Forensic Evidence Chain Genesis Block",
    "version": "1.0.0",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ChainVerificationResult:
    """Result of a full chain integrity verification pass."""
    is_valid: bool
    tamper_detected_at: Optional[int] = None   # block_index where tampering detected
    verified_blocks: int = 0
    total_blocks: int = 0
    chain_head_hash: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class BlockchainLedgerService:
    """
    Manages a SHA-256 hash-chain ledger stored in PostgreSQL.

    Each block links to the previous via prev_hash, making any retrospective
    modification detectable through verify_chain().

    Usage::

        ledger = BlockchainLedgerService()
        block  = await ledger.add_event(db, case_id, "ANALYSIS_STARTED", analyst_id, {...})
        report = await ledger.verify_chain(db)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_or_create_genesis(self, db: AsyncSession) -> BlockchainLedger:
        """
        Ensure the genesis block (index 0) exists in the database.
        Idempotent — safe to call multiple times.
        """
        stmt = select(BlockchainLedger).where(BlockchainLedger.block_index == 0)
        genesis = (await db.execute(stmt)).scalar_one_or_none()
        if not genesis:
            genesis = await self._create_block(
                db, None, "GENESIS", "system", GENESIS_DATA
            )
        return genesis

    async def add_event(
        self,
        db: AsyncSession,
        case_id: Optional[str],
        action: str,
        actor: str,
        data: dict,
    ) -> BlockchainLedger:
        """
        Append a new block to the chain for any investigation event.

        Parameters
        ----------
        case_id : Optional[str]
            The case this event belongs to (None for system-wide events).
        action  : str
            Short action label, e.g. "ANALYSIS_STARTED", "IOC_ADDED".
        actor   : str
            Identifier of the user or system component creating the block.
        data    : dict
            Arbitrary JSON-serialisable payload stored alongside the block.
        """
        await self.get_or_create_genesis(db)
        return await self._create_block(db, case_id, action, actor, data)

    async def verify_chain(
        self,
        db: AsyncSession,
        case_id: Optional[str] = None,
    ) -> ChainVerificationResult:
        """
        Verify the integrity of the entire chain (or a case-scoped subset).

        For each block:
          1. Recompute block_hash and compare to stored value.
          2. Verify prev_hash links to the previous block's block_hash.

        Returns a ChainVerificationResult indicating the first tampered block
        (if any) and the total number of verified blocks.
        """
        stmt = select(BlockchainLedger).order_by(BlockchainLedger.block_index)
        if case_id:
            # Include genesis block (index 0) so the chain can be anchored.
            stmt = stmt.where(
                (BlockchainLedger.case_id == case_id)
                | (BlockchainLedger.block_index == 0)
            )

        blocks = (await db.execute(stmt)).scalars().all()

        if not blocks:
            return ChainVerificationResult(is_valid=False, error="No blocks found")

        tamper_detected_at: Optional[int] = None
        verified_count = 0

        for i, block in enumerate(blocks):
            # Recompute the expected block hash.
            expected_hash = self._compute_block_hash(
                block.block_index,
                block.prev_hash,
                block.timestamp,
                block.case_id,
                block.action,
                block.actor,
                block.data_hash,
            )

            if expected_hash != block.block_hash:
                tamper_detected_at = block.block_index
                break

            # Verify prev_hash linkage against the preceding block in the ledger.
            if block.block_index > 0:
                prev_stmt = select(BlockchainLedger.block_hash).where(
                    BlockchainLedger.block_index == block.block_index - 1
                )
                actual_prev_hash = (await db.execute(prev_stmt)).scalar_one_or_none()
                if actual_prev_hash and block.prev_hash != actual_prev_hash:
                    tamper_detected_at = block.block_index
                    break

            verified_count += 1

        return ChainVerificationResult(
            is_valid=tamper_detected_at is None,
            tamper_detected_at=tamper_detected_at,
            verified_blocks=verified_count,
            total_blocks=len(blocks),
            chain_head_hash=blocks[-1].block_hash if blocks else None,
        )

    async def anchor_to_polygon(
        self, db: AsyncSession, block: BlockchainLedger
    ) -> Optional[str]:
        """
        Anchor the chain head hash to the Polygon Amoy testnet (chain ID 80002).

        Requires environment variables:
          ENABLE_BLOCKCHAIN_ANCHORING=true
          POLYGON_RPC_URL
          POLYGON_PRIVATE_KEY
          POLYGON_ACCOUNT_ADDRESS

        Returns the transaction hash on success, None otherwise.
        """
        enable = (
            __import__("os").getenv("ENABLE_BLOCKCHAIN_ANCHORING", "false").lower()
            == "true"
        )
        polygon_rpc = __import__("os").getenv("POLYGON_RPC_URL")
        private_key = __import__("os").getenv("POLYGON_PRIVATE_KEY")
        account_address = __import__("os").getenv("POLYGON_ACCOUNT_ADDRESS")

        if not enable or not private_key or not account_address:
            return None

        try:
            from web3 import Web3

            w3 = Web3(Web3.HTTPProvider(polygon_rpc))

            nonce = w3.eth.get_transaction_count(account_address)
            tx = {
                "nonce": nonce,
                "to": account_address,
                "value": 0,
                "gas": 21000,
                "gasPrice": w3.eth.gas_price,
                # Encode the first 32 chars of the hash as calldata.
                "data": w3.to_hex(text=block.block_hash[:32]),
                "chainId": 80002,  # Polygon Amoy testnet
            }

            signed = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            tx_hash_hex = w3.to_hex(tx_hash)

            # Persist the tx hash on the block record.
            block.polygon_tx_hash = tx_hash_hex
            block.is_anchored = True
            await db.commit()

            return tx_hash_hex

        except Exception:
            return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _create_block(
        self,
        db: AsyncSession,
        case_id: Optional[str],
        action: str,
        actor: str,
        data: dict,
    ) -> BlockchainLedger:
        """
        Compute hashes and insert a new block at the tail of the chain.

        Sequence:
          1. Find the current maximum block_index (MAX query).
          2. Fetch the prev_hash from that block.
          3. Compute data_hash = SHA-256(JSON(data)).
          4. Compute block_hash = SHA-256(index | prev_hash | ts | ... | data_hash).
          5. Insert and commit.
        """
        # Determine next block index and previous hash.
        stmt = select(func.max(BlockchainLedger.block_index))
        max_index = (await db.execute(stmt)).scalar()

        if max_index is None:
            # This is the genesis block.
            block_index = 0
            prev_hash = "0" * 64
        else:
            block_index = max_index + 1
            stmt2 = select(BlockchainLedger.block_hash).where(
                BlockchainLedger.block_index == max_index
            )
            prev_hash = (await db.execute(stmt2)).scalar_one()

        timestamp = datetime.now(timezone.utc)
        data_hash = self._hash_data(data)
        block_hash = self._compute_block_hash(
            block_index, prev_hash, timestamp, case_id, action, actor, data_hash
        )

        block = BlockchainLedger(
            id=uuid.uuid4(),
            block_index=block_index,
            prev_hash=prev_hash,
            timestamp=timestamp,
            case_id=case_id,
            action=action,
            actor=actor,
            data=data,
            data_hash=data_hash,
            block_hash=block_hash,
            is_anchored=False,
        )
        db.add(block)
        await db.commit()
        await db.refresh(block)
        return block

    @staticmethod
    def _hash_data(data: dict) -> str:
        """Return SHA-256 hex digest of the JSON-serialised data dict."""
        serialised = json.dumps(data, sort_keys=True, default=str).encode()
        return hashlib.sha256(serialised).hexdigest()

    @staticmethod
    def _compute_block_hash(
        block_index: int,
        prev_hash: str,
        timestamp: datetime,
        case_id: Optional[str],
        action: str,
        actor: str,
        data_hash: str,
    ) -> str:
        """
        Compute the SHA-256 block hash from all identifying block fields.

        Content string (pipe-delimited):
          block_index | prev_hash | iso_timestamp | case_id | action | actor | data_hash
        """
        content = (
            f"{block_index}:{prev_hash}:{timestamp.isoformat()}:"
            f"{case_id}:{action}:{actor}:{data_hash}"
        )
        return hashlib.sha256(content.encode()).hexdigest()
