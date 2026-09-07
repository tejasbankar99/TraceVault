"""
blockchain_service.py — alias for blockchain_ledger module.
Routers import BlockchainService from here.
"""
from app.services.blockchain_ledger import BlockchainLedgerService as BlockchainService  # noqa: F401
