from proofmesh.crypto import CTX_MANIFEST, CTX_EVENT, SigningKey, check_certificate, issue_certificate, verify_signature


def test_sign_and_verify_with_context_separation():
    k = SigningKey.generate()
    body = {"a": 1, "b": [1, 2]}
    sig = k.sign(CTX_MANIFEST, body)
    assert verify_signature(k.public_key_b64, CTX_MANIFEST, body, sig)
    assert verify_signature(k.public_key_b64, CTX_MANIFEST, {"b": [1, 2], "a": 1}, sig)  # canonical
    assert not verify_signature(k.public_key_b64, CTX_EVENT, body, sig)
    assert not verify_signature(k.public_key_b64, CTX_MANIFEST, {"a": 2, "b": [1, 2]}, sig)
    assert not verify_signature(SigningKey.generate().public_key_b64, CTX_MANIFEST, body, sig)
    assert not verify_signature(k.public_key_b64, CTX_MANIFEST, body, "not-base64!")


def test_key_roundtrip(tmp_path):
    k = SigningKey.generate()
    k.save(tmp_path / "k.pem")
    assert (tmp_path / "k.pem").stat().st_mode & 0o777 == 0o600
    k2 = SigningKey.load(tmp_path / "k.pem")
    assert k2.public_key_b64 == k.public_key_b64


def test_certificates():
    authority, rogue, dept = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    cert = issue_certificate(authority, "finance", dept.public_key_b64, "2026-01-01T00:00:00Z")
    assert check_certificate(cert, authority.public_key_b64)[0]
    forged = issue_certificate(rogue, "finance", dept.public_key_b64, "2026-01-01T00:00:00Z")
    assert not check_certificate(forged, authority.public_key_b64)[0]
    swapped = {"certificate": {**cert["certificate"], "public_key": rogue.public_key_b64}, "signature": cert["signature"]}
    assert not check_certificate(swapped, authority.public_key_b64)[0]
    renamed = {"certificate": {**cert["certificate"], "domain": "hr"}, "signature": cert["signature"]}
    assert not check_certificate(renamed, authority.public_key_b64)[0]
