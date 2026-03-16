import json, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

class OpenClaim:

    @staticmethod
    def canonicalize(obj):
        clone = dict(obj)
        clone.pop("sig", None)
        return json.dumps(clone, sort_keys=True, separators=(',',':'))

    @staticmethod
    def sign(claim, private_key):
        canon = OpenClaim.canonicalize(claim).encode()
        signature = private_key.sign(canon, ec.ECDSA(hashes.SHA256()))
        claim["sig"] = base64.b64encode(signature).decode()
        return claim

    @staticmethod
    def verify(claim, public_key):
        sig = claim.get("sig")
        if not sig: return False
        canon = OpenClaim.canonicalize(claim).encode()
        signature = base64.b64decode(sig)
        try:
            public_key.verify(signature, canon, ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False