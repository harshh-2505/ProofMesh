"""ProofMesh: a cryptographically verifiable data mesh."""

from .contract import ContractError, PolicyViolation
from .mesh import IntegrityError, NotFound, ProofMesh, ProofMeshError
from .verify import Verifier, audit, verify_event_log, verify_file

__version__ = "0.1.0"

__all__ = [
    "ContractError",
    "IntegrityError",
    "NotFound",
    "PolicyViolation",
    "ProofMesh",
    "ProofMeshError",
    "Verifier",
    "audit",
    "verify_event_log",
    "verify_file",
]
