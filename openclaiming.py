# Optional strict canonicalizer:
# pip install rfc8785
# https://github.com/trailofbits/rfc8785.py
#
# Required crypto package:
# pip install cryptography

import json
import base64
import urllib.request
import time
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization

try:
	import rfc8785
	STRICT = True
except ImportError:
	STRICT = False


class OpenClaim:

	# ---------- CACHE ----------

	_FETCH_TTL = 60  # seconds, matching the JS 60_000 ms ttl

	_url_cache = {}
	_url_cache_time = {}

	_key_cache = {}
	_key_cache_time = {}

	_pubkey_cache = {}
	_pubkey_cache_time = {}

	# ---------- TIME ----------

	@staticmethod
	def _now():
		return time.time()

	@staticmethod
	def _get_cache(map_obj, time_map, key):
		if key not in map_obj:
			return None

		t = time_map.get(key, 0)

		if (OpenClaim._now() - t) > OpenClaim._FETCH_TTL:
			map_obj.pop(key, None)
			time_map.pop(key, None)
			return None

		return map_obj[key]

	@staticmethod
	def _set_cache(map_obj, time_map, key, value):
		map_obj[key] = value
		time_map[key] = OpenClaim._now()

	# ---------- EXISTING ----------

	@staticmethod
	def normalize(v):

		if isinstance(v, list):
			return [OpenClaim.normalize(x) for x in v]

		if isinstance(v, dict):
			return {k: OpenClaim.normalize(v[k]) for k in sorted(v)}

		if isinstance(v, (int, float)) and not isinstance(v, bool):
			return str(v)

		return v

	@staticmethod
	def to_array(v):
		if v is None:
			return []
		return v if isinstance(v, list) else [v]

	@staticmethod
	def normalize_signatures(v):
		arr = OpenClaim.to_array(v)
		return [None if x is None else str(x) for x in arr]

	@staticmethod
	def ensure_string_keys(keys):
		for k in keys:
			if not isinstance(k, str):
				raise Exception("OpenClaim: all keys must be strings")

	@staticmethod
	def ensure_unique_keys(keys):
		seen = set()

		for k in keys:
			if k in seen:
				raise Exception("OpenClaim: duplicate keys are not allowed")
			seen.add(k)

	@staticmethod
	def ensure_sorted_keys(keys):
		sorted_keys = sorted(keys)

		for i in range(len(keys)):
			if keys[i] != sorted_keys[i]:
				raise Exception("OpenClaim: key array must be lexicographically sorted")

	# ---------- PEM / DER ----------

	@staticmethod
	def strip_pem_headers(pem):
		return (
			str(pem)
			.replace("-----BEGIN PUBLIC KEY-----", "")
			.replace("-----END PUBLIC KEY-----", "")
			.replace("\r", "")
			.replace("\n", "")
			.strip()
		)

	@staticmethod
	def der_to_pem(base64_der):
		body = str(base64_der).replace("\r", "").replace("\n", "").strip()
		lines = [body[i:i+64] for i in range(0, len(body), 64)]

		return "\n".join([
			"-----BEGIN PUBLIC KEY-----",
			*lines,
			"-----END PUBLIC KEY-----"
		])

	@staticmethod
	def pem_to_der(pem):
		return OpenClaim.strip_pem_headers(str(pem))

	@staticmethod
	def is_pem_public_key(v):
		return isinstance(v, str) and "BEGIN PUBLIC KEY" in v

	@staticmethod
	def to_es256_key_string_from_public_pem(public_key_pem):
		return "data:key/es256;base64," + OpenClaim.pem_to_der(public_key_pem)

	@staticmethod
	def to_base64_der_string(value):
		if isinstance(value, bytes):
			return base64.b64encode(value).decode()

		if isinstance(value, bytearray):
			return base64.b64encode(bytes(value)).decode()

		if isinstance(value, str):
			return value

		return str(value)

	# ---------- HASH ----------

	@staticmethod
	def sha256(buf_or_string):
		if isinstance(buf_or_string, str):
			buf_or_string = buf_or_string.encode()
		return hashlib.sha256(buf_or_string).digest()

	# ---------- CANONICALIZATION ----------

	@staticmethod
	def fallback_canonicalize(obj):
		n = OpenClaim.normalize(obj)

		return json.dumps(
			n,
			separators=(",", ":"),
			ensure_ascii=False
		).encode()

	@staticmethod
	def canonicalize(claim):
		obj = dict(claim)
		obj.pop("sig", None)

		if STRICT:
			try:
				if hasattr(rfc8785, "dumps"):
					out = rfc8785.dumps(obj)
					return out if isinstance(out, bytes) else str(out).encode()

				if hasattr(rfc8785, "canonicalize"):
					out = rfc8785.canonicalize(obj)
					return out if isinstance(out, bytes) else str(out).encode()
			except Exception:
				pass

		return OpenClaim.fallback_canonicalize(obj)

	# ---------- FETCH ----------

	@staticmethod
	def fetch_json(url):

		cached = OpenClaim._get_cache(OpenClaim._url_cache, OpenClaim._url_cache_time, url)
		if cached is not None:
			return cached

		json_obj = None

		try:
			with urllib.request.urlopen(url) as f:
				raw = f.read().decode()
				json_obj = json.loads(raw)
		except Exception:
			json_obj = None

		OpenClaim._set_cache(OpenClaim._url_cache, OpenClaim._url_cache_time, url, json_obj)
		return json_obj

	@staticmethod
	def clear_fetch_cache(url=None):
		if url is None:
			OpenClaim._url_cache = {}
			OpenClaim._url_cache_time = {}
		else:
			OpenClaim._url_cache.pop(url, None)
			OpenClaim._url_cache_time.pop(url, None)

	# ---------- PUBLIC KEY CACHE ----------

	@staticmethod
	def get_cached_public_key(base64_der):

		cached = OpenClaim._get_cache(OpenClaim._pubkey_cache, OpenClaim._pubkey_cache_time, base64_der)
		if cached is not None:
			return cached

		der = base64.b64decode(base64_der)
		pub = serialization.load_der_public_key(der)

		OpenClaim._set_cache(OpenClaim._pubkey_cache, OpenClaim._pubkey_cache_time, base64_der, pub)
		return pub

	# ---------- NEW: DATA KEY PARSER ----------

	@staticmethod
	def parse_data_key(key_str):

		if not isinstance(key_str, str):
			return None

		if not key_str.startswith("data:key/"):
			return None

		idx = key_str.find(",")
		if idx < 0:
			return None

		meta = key_str[5:idx]  # key/...
		data = key_str[idx + 1:]

		parts = meta.split(";")
		type_part = parts[0]
		fmt = type_part.replace("key/", "").upper()

		encoding = "raw"

		for p in parts[1:]:
			if p == "base64":
				encoding = "base64"
			if p == "base64url":
				encoding = "base64url"

		value = data

		if encoding == "base64":
			value = base64.b64decode(data)

		if encoding == "base64url":
			remainder = len(data) % 4
			padding = "=" * (4 - remainder) if remainder else ""
			b64 = data.replace("-", "+").replace("_", "/") + padding
			value = base64.b64decode(b64)

		return {
			"fmt": fmt,
			"value": value
		}

	# ---------- KEY RESOLUTION ----------

	@staticmethod
	def resolve_key(key_str, seen=None):

		if seen is None:
			seen = set()

		if key_str in seen:
			raise Exception("OpenClaim: cyclic key reference detected")

		cached = OpenClaim._get_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str)
		if cached is not None:
			return cached

		if not key_str or not isinstance(key_str, str):
			return None

		next_seen = set(seen)
		next_seen.add(key_str)

		# --- DATA URL ---
		if key_str.startswith("data:key/"):
			parsed = OpenClaim.parse_data_key(key_str)
			if parsed:
				OpenClaim._set_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str, parsed)
				return parsed

		# --- URL ---
		if key_str.startswith("http://") or key_str.startswith("https://"):

			parts = key_str.split("#")
			url = parts[0]
			path = parts[1:]

			json_obj = OpenClaim.fetch_json(url)

			if not json_obj:
				OpenClaim._set_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str, None)
				return None

			current = json_obj

			for p in path:
				if not p:
					continue

				if isinstance(current, dict):
					current = current.get(p)
				else:
					current = None

				if current is None:
					OpenClaim._set_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str, None)
					return None

			# allow array of keys
			if isinstance(current, list):
				OpenClaim._set_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str, current)
				return current

			if isinstance(current, str):
				resolved = OpenClaim.resolve_key(current, next_seen)
				OpenClaim._set_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str, resolved)
				return resolved

			OpenClaim._set_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str, None)
			return None

		# --- LEGACY ---
		idx = key_str.find(":")
		if idx <= 0:
			return None

		scheme = key_str[:idx].upper()
		rest = key_str[idx + 1:]

		result = {
			"fmt": scheme,
			"value": rest
		}

		OpenClaim._set_cache(OpenClaim._key_cache, OpenClaim._key_cache_time, key_str, result)
		return result

	# ---------- SORTED STATE ----------

	@staticmethod
	def build_sorted_key_state(keys_input, signatures_input):
		keys = OpenClaim.to_array(keys_input)[:]
		signatures = OpenClaim.normalize_signatures(signatures_input)

		OpenClaim.ensure_string_keys(keys)
		OpenClaim.ensure_unique_keys(keys)

		if len(signatures) > len(keys):
			raise Exception("OpenClaim: signature array cannot be longer than key array")

		pairs = []

		for i, key in enumerate(keys):
			pairs.append({
				"key": key,
				"sig": signatures[i] if i < len(signatures) else None
			})

		pairs.sort(key=lambda p: p["key"])

		sorted_keys = [p["key"] for p in pairs]
		sorted_signatures = [p["sig"] for p in pairs]

		OpenClaim.ensure_sorted_keys(sorted_keys)

		return {
			"keys": sorted_keys,
			"signatures": sorted_signatures
		}

	# ---------- POLICY ----------

	@staticmethod
	def parse_verify_policy(policy, total_keys):
		if policy is None:
			return {"minValid": 1}

		if isinstance(policy, int):
			return {"minValid": policy}

		if policy.get("mode") == "all":
			return {"minValid": total_keys}

		if isinstance(policy.get("minValid"), int):
			return {"minValid": policy.get("minValid")}

		return {"minValid": 1}

	# ---------- SIGN ----------

	@staticmethod
	def sign(claim, private_key, existing=None):
		if existing is None:
			existing = {}

		pub = private_key.public_key()

		pub_der = pub.public_bytes(
			encoding=serialization.Encoding.DER,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		signer_key = "data:key/es256;base64," + base64.b64encode(pub_der).decode()

		keys = existing.get("keys") if "keys" in existing else claim.get("key")
		signatures = existing.get("signatures") if "signatures" in existing else claim.get("sig")

		keys = OpenClaim.to_array(keys)
		signatures = OpenClaim.normalize_signatures(signatures)

		if not keys:
			keys = [signer_key]
		elif signer_key not in keys:
			keys = keys + [signer_key]

		state = OpenClaim.build_sorted_key_state(keys, signatures)
		signer_index = state["keys"].index(signer_key)

		tmp = dict(claim)
		tmp["key"] = state["keys"]
		tmp["sig"] = state["signatures"]

		canon = OpenClaim.canonicalize(tmp)
		hash_bytes = OpenClaim.sha256(canon)

		sig = private_key.sign(
			hash_bytes,
			ec.ECDSA(utils.Prehashed(hashes.SHA256()))
		)

		state["signatures"][signer_index] = base64.b64encode(sig).decode()

		return {
			**claim,
			"key": state["keys"],
			"sig": state["signatures"]
		}

	# ---------- VERIFY ----------

	@staticmethod
	def verify(claim, policy=None):
		if policy is None:
			policy = {}

		keys = OpenClaim.to_array(claim.get("key"))
		signatures = OpenClaim.normalize_signatures(claim.get("sig"))

		if not keys:
			raise Exception("OpenClaim: missing public keys")

		state = OpenClaim.build_sorted_key_state(keys, signatures)
		keys = state["keys"]
		signatures = state["signatures"]

		tmp = dict(claim)
		tmp["key"] = keys
		tmp["sig"] = signatures

		canon = OpenClaim.canonicalize(tmp)
		hash_bytes = OpenClaim.sha256(canon)

		valid = 0

		for i in range(len(keys)):

			sig = signatures[i]
			if not sig:
				continue

			key_obj = OpenClaim.resolve_key(keys[i])

			key_objs = key_obj if isinstance(key_obj, list) else [key_obj]

			for ko in key_objs:

				if not ko:
					continue

				if ko.get("fmt") == "ES256":
					der_b64 = OpenClaim.to_base64_der_string(ko.get("value"))

					try:
						pub = OpenClaim.get_cached_public_key(der_b64)
					except Exception:
						continue

					try:
						pub.verify(
							base64.b64decode(sig),
							hash_bytes,
							ec.ECDSA(utils.Prehashed(hashes.SHA256()))
						)
						valid += 1
						break
					except Exception:
						pass

				if ko.get("fmt") == "EIP712":
					if hasattr(OpenClaim, "EVM") and OpenClaim.EVM and hasattr(OpenClaim.EVM, "verify_key"):
						try:
							if OpenClaim.EVM.verify_key(claim, ko, sig):
								valid += 1
								break
						except Exception:
							pass

		return valid >= OpenClaim.parse_verify_policy(policy, len(keys))["minValid"]