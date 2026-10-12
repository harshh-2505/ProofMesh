"""Vercel entrypoint.

The hosted site runs ProofMesh in lab mode: every request works on a throwaway
copy of a deterministic demo mesh in /tmp, so serverless instances need no
database or storage of their own. The node API (persistent, token-protected)
is switched off here; run ``proofmesh serve`` to get it.
"""

import os

os.environ.setdefault("PROOFMESH_MODE", "lab")

from proofmesh.api import app  # noqa: E402

__all__ = ["app"]
