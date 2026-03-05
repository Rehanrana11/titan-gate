import hashlib

MERKLE_ALGORITHM = "merkle_v1"
EMPTY_HASH = hashlib.sha256(b"L|EMPTY").hexdigest()


def leaf_hash(leaf_string: str) -> str:
    return hashlib.sha256(b"L|" + leaf_string.encode("utf-8")).hexdigest()


def node_hash(left: str, right: str) -> str:
    return hashlib.sha256(
        b"N|" + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def compute_merkle_root(leaves: list) -> str:
    if not leaves:
        return EMPTY_HASH
    hashes = [leaf_hash(l) for l in sorted(leaves)]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [
            node_hash(hashes[i], hashes[i + 1])
            for i in range(0, len(hashes), 2)
        ]
    return hashes[0]


def make_leaf_string(tenant_id, root_date, receipt_id, receipt_hash):
    return "v1|{}|{}|{}|{}".format(tenant_id, root_date, receipt_id, receipt_hash)
