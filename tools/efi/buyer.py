#!/usr/bin/env python3
"""The buyer identifier of a canonical request, read the way the circuits read it.

Mirror of noir/pf_efi/src/buyer.nr; tools/efi/test_buyer.py checks the two against each other.
The identifier is the text `IDType:IDNum` as one big-endian number.

  python3 tools/efi/buyer.py request.xml        # canonical request without its signature
"""
import sys

BUYER_WINDOW = 400
SIZE = 2048  # bytes a batch circuit reserves for one request

UPPER = set(range(65, 91))
ALNUM = UPPER | set(range(48, 58)) | set(range(97, 123))


class BuyerError(ValueError):
    """The reader refuses this request."""


def pack(id_type: str, id_num: str) -> int:
    return int.from_bytes(f"{id_type}:{id_num}".encode("ascii"), "big")


def unpack(identifier: int) -> str:
    return identifier.to_bytes((identifier.bit_length() + 7) // 8, "big").decode("ascii")


def _value(arr: bytes, at: int, longest: int, allowed, problem: str, shortest: int) -> bytes:
    window = arr[at:at + longest + 1]
    end = window.find(b'"')
    if end < shortest or any(c not in allowed for c in window[:end if end >= 0 else None]):
        raise BuyerError(problem)
    return window[:end]


def buyer_id(doc: bytes, doc_len=None, size: int = SIZE) -> int:
    signed = len(doc) if doc_len is None else doc_len
    if signed > size or len(doc) > size:
        raise BuyerError("document longer than the circuit allows")
    arr = doc + bytes(size - len(doc))

    hits = [i for i in range(size - 6) if arr[i:i + 7] == b"<Buyer "]
    if len(hits) != 1:
        raise BuyerError("<Buyer> is missing or repeated")
    start = hits[0] + 6
    if start + BUYER_WINDOW + 9 > size:
        raise BuyerError("<Buyer> begins too close to the end of the array")

    in_quote, in_tag, tag_end = False, True, None
    num_at, type_at, single_quotes, whitespace = [], [], 0, 0
    for i in range(start, start + BUYER_WINDOW):
        outside = in_tag and not in_quote
        if outside and arr[i:i + 8] == b' IDNum="':
            num_at.append(i + 8)
        if outside and arr[i:i + 9] == b' IDType="':
            type_at.append(i + 9)
        b = arr[i]
        single_quotes += outside and b == 39
        whitespace += outside and b in (9, 10, 13)
        if outside and b == 62:
            tag_end, in_tag = i, False
        if b == 34:
            in_quote = not in_quote
    if in_tag:
        raise BuyerError("<Buyer> start tag does not close inside the scan window")
    if single_quotes:
        raise BuyerError("single quote at tag level")
    if whitespace:
        raise BuyerError("tab or line break at tag level")
    if len(num_at) != 1:
        raise BuyerError("IDNum is missing or repeated")
    if len(type_at) != 1:
        raise BuyerError("IDType is missing or repeated")

    id_type = _value(arr, type_at[0], 4, UPPER, "IDType is not 2 to 4 capital letters", 2)
    for c in arr[num_at[0]:num_at[0] + 21].split(b'"')[0]:
        if c not in ALNUM:
            raise BuyerError("IDNum has a character outside 0-9, A-Z, a-z")
    id_num = _value(arr, num_at[0], 20, ALNUM, "IDNum is empty or longer than 20 characters", 1)
    if not tag_end + 35 < signed:
        raise BuyerError("<Buyer> lies outside the signed document")
    return pack(id_type.decode(), id_num.decode())


if __name__ == "__main__":
    try:
        print(unpack(buyer_id(open(sys.argv[1], "rb").read())))
    except BuyerError as e:
        sys.exit(f"refused: {e}")
