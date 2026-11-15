"""Country formats the tools read. Mirrors noir/pf_efi/src/format.nr: the two must stay byte-identical.

The fiscalization systems read here exchange the same two signed messages and sign them the same
way. A format holds what differs from one country to the other: the address of the schema, the
version, how the response is spelled, and whether every invoice names a device (TCRCode).

  me  Montenegro. Written against the published schema and real messages of the tax
      administration's test environment.
  al  Albania. Written against the published specification only ("Fiscalization Service, Technical
      Specification", version 09). No real signed message has been seen; the response is spelled as
      in the specification's example, with the prefix ns2. A non-cash invoice carries no device
      code there. Only the statement about one buyer is built for this format.

Each format has its own circuits, so a proof made for one does not verify under the keys of
another. The format of a file is read from the file itself (the namespace of its root element).
"""
import re
from dataclasses import dataclass

ZERO_UUID = b"00000000-0000-0000-0000-000000000000"
ZERO_TIME = b"0000-00-00T00:00:00+00:00"


@dataclass(frozen=True)
class Format:
    name: str               # short name: command line, circuit names, statement.json
    country: str
    namespace: str
    version: str
    response_prefix: str    # prefix the response elements are written with; "" for the default namespace
    device_required: bool   # every invoice names its device (TCRCode)
    basis: str              # what the format was written against
    currency: str           # the currency invoices are in unless they say otherwise
    party_id_type: str      # the kind of identifier domestic companies carry, for invented invoices
    country_code: str
    one_buyer_circuits: tuple   # circuit names by number of slots: ((1, name), (10, name))
    has_batch_circuits: bool    # the statements about a consecutive run are built for this format

    # --- request ---
    @property
    def request_head(self) -> bytes:
        """The canonical request from its first byte up to the value of SendDateTime."""
        return (f'<RegisterInvoiceRequest xmlns="{self.namespace}" Id="Request" Version="{self.version}">'
                f'<Header SendDateTime="').encode()

    @property
    def tag_start(self) -> int:
        """Offset, in a canonical request, of the space right after `<Invoice`."""
        return len(self.request_head) + 88

    @property
    def header_re(self):
        return re.compile(re.escape(self.request_head) + rb'[^"]{25}" UUID="[^"]{36}"></Header><Invoice ')

    # --- response ---
    def _response_parts(self):
        p = self.response_prefix + ":" if self.response_prefix else ""
        decl = f"xmlns:{self.response_prefix}" if self.response_prefix else "xmlns"
        return (
            f'<{p}RegisterInvoiceResponse {decl}="{self.namespace}" Id="Response" Version="{self.version}">'
            f'<{p}Header RequestUUID="'.encode(),
            b'" SendDateTime="',
            b'" UUID="',
            f'"></{p}Header><{p}FIC>'.encode(),
            f"</{p}FIC></{p}RegisterInvoiceResponse>".encode(),
        )

    def build_response(self, req_uuid: bytes, send_dt: bytes, resp_uuid: bytes, fic: bytes) -> bytes:
        """The canonical response for these four values."""
        p0, p1, p2, p3, p4 = self._response_parts()
        return p0 + req_uuid + p1 + send_dt + p2 + resp_uuid + p3 + fic + p4

    @property
    def response_template(self) -> bytes:
        """The canonical response with zeros where its four values go, as format.nr has it."""
        return self.build_response(ZERO_UUID, ZERO_TIME, ZERO_UUID, ZERO_UUID)

    @property
    def response_re(self):
        p0, p1, p2, p3, p4 = self._response_parts()
        return re.compile(re.escape(p0) + b"(.{36})" + re.escape(p1) + b"(.{25})" + re.escape(p2)
                          + b"(.{36})" + re.escape(p3) + b"(.{36})" + re.escape(p4), re.S)

    def one_buyer_circuit(self, slots: int) -> str:
        return dict(self.one_buyer_circuits)[slots]


MONTENEGRO = Format(
    name="me", country="Montenegro", namespace="https://efi.tax.gov.me/fs/schema", version="1",
    response_prefix="", device_required=True,
    basis="the published schema and real messages of the test environment",
    currency="EUR", party_id_type="TIN", country_code="MNE",
    one_buyer_circuits=((1, "debtor_k1"), (10, "debtor_k10")), has_batch_circuits=True,
)

ALBANIA = Format(
    name="al", country="Albania", namespace="https://eFiskalizimi.tatime.gov.al/FiscalizationService/schema",
    version="3", response_prefix="ns2", device_required=False,
    basis="the published specification only; no real signed message has been seen",
    currency="ALL", party_id_type="NUIS", country_code="ALB",
    one_buyer_circuits=((1, "debtor_al_k1"), (10, "debtor_al_k10")), has_batch_circuits=False,
)

ALL = (MONTENEGRO, ALBANIA)


class UnknownFormat(ValueError):
    pass


def by_name(name: str) -> Format:
    for f in ALL:
        if f.name == name:
            return f
    raise UnknownFormat(f"unknown format {name!r}; known: " + ", ".join(f.name for f in ALL))


def by_namespace(namespace: str):
    return next((f for f in ALL if f.namespace == namespace), None)


def of_request(doc: bytes) -> Format:
    """The format a canonical request is written in."""
    for f in ALL:
        if doc.startswith(f.request_head):
            return f
    raise UnknownFormat("the request is not in a format this tool reads (header template)")


def of_response(doc: bytes) -> Format:
    """The format a canonical response is written in."""
    for f in ALL:
        if f.response_re.fullmatch(doc):
            return f
    raise UnknownFormat("the response is not in a format this tool reads (canonical template)")
