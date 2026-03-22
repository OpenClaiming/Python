# Optional strict canonicalizer:
# pip install rfc8785
# https://github.com/trailofbits/rfc8785.py

import json
import base64
import urllib.request
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

try:
	import rfc8785
	STRICT = True
except ImportError:
	STRICT = False


class OpenClaim:

	# ---------- CACHE ----------

	_fetch_cache = {}
	_fetch_cache_time = {}
	_fetch_ttl = 300  # seconds


	@staticmethod
	def _fetch_cached(url):

		now = time.time()

		if url in OpenClaim._fetch_cache:
			t = OpenClaim._fetch_cache_time.get(url, 0)
			if (now - t) < OpenClaim._fetch_ttl:
				return OpenClaim._fetch_cache[url]

		data = None

		try:
			with urllib.request.urlopen(url) as f:
				data = f.read().decode()
		except Exception:
			pass

		# cache even failures
		OpenClaim._fetch_cache[url] = data
		OpenClaim._fetch_cache_time[url] = now

		return data


	@staticmethod
	def clear_fetch_cache(url=None):
		if url is None:
			OpenClaim._fetch_cache = {}
			OpenClaim._fetch_cache_time = {}
		else:
			OpenClaim._fetch_cache.pop(url, None)
			OpenClaim._fetch_cache_time.pop(url, None)


	@staticmethod
	def normalize(v):

		if isinstance(v, dict):
			return {k: OpenClaim.normalize(v[k]) for k in sorted(v)}

		if isinstance(v, list):
			return [OpenClaim.normalize(x) for x in v]

		return v


	@staticmethod
	def fallback_canonicalize(obj):

		n = OpenClaim.normalize(obj)

		return json.dumps(
			n,
			separators=(",",":")
		).encode()


	@staticmethod
	def canonicalize(claim):

		obj = dict(claim)

		obj.pop("sig", None)

		if STRICT:
			try:
				return rfc8785.canonicalize(obj)
			except Exception:
				pass

		return OpenClaim.fallback_canonicalize(obj)


	# ---------- NEW HELPERS ----------

	@staticmethod
	def to_array(v):
		if v is None:
			return []
		return v if isinstance(v, list) else [v]


	@staticmethod
	def ensure_sorted(keys):
		if keys != sorted(keys):
			raise Exception("keys must be lexicographically sorted")


	@staticmethod
	def pem_to_der(pem):
		return (
			pem
			.replace("-----BEGIN PUBLIC KEY-----", "")
			.replace("-----END PUBLIC KEY-----", "")
			.replace("\n", "")
			.strip()
		)


	@staticmethod
	def der_to_public_key(base64_der):
		der = base64.b64decode(base64_der)
		return serialization.load_der_public_key(der)


	@staticmethod
	def resolve_key(key_str):

		if not isinstance(key_str, str):
			return None

		if ":" not in key_str:
			return None

		scheme, rest = key_str.split(":", 1)
		typ = scheme.upper()

		if rest.startswith("http://") or rest.startswith("https://"):

			parts = rest.split("#")
			url = parts[0]

			raw = OpenClaim._fetch_cached(url)
			if raw is None:
				return None

			try:
				data = json.loads(raw)
			except Exception:
				return None

			current = data

			for p in parts[1:]:
				if not p:
					continue

				if not isinstance(current, dict):
					return None

				current = current.get(p)

				if current is None:
					return None

			if not isinstance(current, str):
				return None

			return {"typ": typ, "value": current}

		return {"typ": typ, "value": rest}


	# ---------- SIGN ----------

	@staticmethod
	def sign(claim, private_key):
		return OpenClaim.sign_with_existing(claim, private_key, {})


	@staticmethod
	def sign_with_existing(claim, private_key, existing):

		keys = OpenClaim.to_array(existing.get("keys") or claim.get("key"))
		sigs = OpenClaim.to_array(existing.get("signatures") or claim.get("sig"))

		pub = private_key.public_key()

		pub_der = pub.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		key_str = "es256:" + base64.b64encode(pub_der).decode()

		if key_str not in keys:
			keys.append(key_str)

		keys = sorted(keys)
		OpenClaim.ensure_sorted(keys)

		while len(sigs) < len(keys):
			sigs.append(None)

		index = keys.index(key_str)

		tmp = dict(claim)
		tmp["key"] = keys
		tmp["sig"] = sigs

		canon = OpenClaim.canonicalize(tmp)

		sig = private_key.sign(
			canon,
			ec.ECDSA(hashes.SHA256())
		)

		sigs[index] = base64.b64encode(sig).decode()

		out = dict(claim)
		out["key"] = keys
		out["sig"] = sigs

		return out


	# ---------- VERIFY ----------

	@staticmethod
	def verify(claim, public_key):
		return OpenClaim.verify_with_policy(claim, public_key, {})


	@staticmethod
	def verify_with_policy(claim, public_key, policy):

		keys = OpenClaim.to_array(claim.get("key"))
		sigs = OpenClaim.to_array(claim.get("sig"))

		if not keys or not sigs:
			return False

		if len(keys) != len(sigs):
			return False

		OpenClaim.ensure_sorted(keys)

		tmp = dict(claim)
		tmp["key"] = keys
		tmp["sig"] = sigs

		canon = OpenClaim.canonicalize(tmp)

		valid = 0

		for i in range(len(keys)):

			sig_b64 = sigs[i]
			if sig_b64 is None:
				continue

			key_obj = OpenClaim.resolve_key(keys[i])
			if not key_obj:
				continue

			if key_obj["typ"] == "EIP712":
				continue

			if key_obj["typ"] != "ES256":
				continue

			pub = OpenClaim.der_to_public_key(key_obj["value"])

			try:
				pub.verify(
					base64.b64decode(sig_b64),
					canon,
					ec.ECDSA(hashes.SHA256())
				)
				valid += 1
			except Exception:
				pass

		min_valid = policy.get("minValid", 1)

		if policy.get("mode") == "all":
			min_valid = len(keys)

		return valid >= min_valid