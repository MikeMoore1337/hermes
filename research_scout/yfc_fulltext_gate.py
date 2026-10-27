"""I4/#599: bounded, identity-bound Europe PMC OA JATS availability preflight.

Not a text generator, scientific review, copying service or publishing client.
Only metadata/sha256 is returned. Full text stays in process memory and is
never logged, stored, sent to YFC, or treated as evidence of verified claims.
"""
from __future__ import annotations

import hashlib
import http.client
import re
import xml.etree.ElementTree as ET

from .europe_pmc import HOST, PinnedHTTPS, resolve_public

PMCID = re.compile(r"PMC[1-9][0-9]{1,11}\Z")
DOI = re.compile(r"10\.[0-9]{4,9}/[A-Za-z0-9._;()/:-]{1,110}\Z")
MAX_XML = 524_288
MAX_NODES = 15_000
ENDPOINT = "/europepmc/webservices/rest/"


class FulltextHold(ValueError):
    """Fixed refusal code only; never include XML, identifiers or URLs."""



# Europe PMC's JATS XML may declare an *external* public NLM/JATS DTD.
# This reader does not validate a DTD and must NEVER dereference it.
# Only a bounded standard public identifier with an opaque, safe system
# locator is removed BEFORE parsing. Internal subsets and entity declarations
# remain forbidden, including in otherwise valid article XML.
_JATS_PUBLIC_ID = (
    rb'(?:\"-//(?:NLM|JATS)//DTD [A-Za-z0-9 .(),+/_-]{3,190}//EN\"'
    rb'|\'-//(?:NLM|JATS)//DTD [A-Za-z0-9 .(),+/_-]{3,190}//EN\')'
)
_JATS_SYSTEM_ID = (
    rb'(?:\"[A-Za-z0-9:/._-]{1,220}\"'
    rb'|\'[A-Za-z0-9:/._-]{1,220}\')'
)
_SAFE_JATS_DOCTYPE = re.compile(
    rb'<!DOCTYPE[ \t\r\n]+article[ \t\r\n]+PUBLIC[ \t\r\n]+'
    + _JATS_PUBLIC_ID + rb'[ \t\r\n]+' + _JATS_SYSTEM_ID
    + rb'[ \t\r\n]*>', re.IGNORECASE,
)
_XML_PREAMBLE = re.compile(
    rb'(?:\xef\xbb\xbf)?[ \t\r\n]*(?:<\?xml[ \t\r\n]+[^?<>]{1,160}\?>[ \t\r\n]*)?',
    re.IGNORECASE,
)


def xml_without_external_doctype(raw: bytes) -> bytes:
    """Discard one strictly bounded JATS public DOCTYPE, never resolve its URI.

    No DTD, file, network or entity expansion is performed. This function is
    shared by the metadata inspector and the private full-text extractor.
    """
    upper = raw.upper()
    if b'<!ENTITY' in upper or b'<?XML-STYLESHEET' in upper or b'<?XML-MODEL' in upper:
        raise FulltextHold("FULLTEXT_DTD_OR_ENTITY_DENIED")
    if b'<!DOCTYPE' not in upper:
        return raw
    if upper.count(b'<!DOCTYPE') != 1:
        raise FulltextHold("FULLTEXT_DTD_OR_ENTITY_DENIED")
    matched = _SAFE_JATS_DOCTYPE.search(raw)
    if matched is None or _XML_PREAMBLE.fullmatch(raw[:matched.start()]) is None:
        raise FulltextHold("FULLTEXT_DTD_OR_ENTITY_DENIED")
    # Internal subsets, custom declarations, arbitrary DOCTYPE forms and
    # multiple declarations never match the bounded PUBLIC-only pattern.
    return raw[:matched.start()] + raw[matched.end():]

def _identity(pmcid: str, doi: str | None = None) -> None:
    if type(pmcid) is not str or PMCID.fullmatch(pmcid) is None:
        raise FulltextHold("PMCID_NOT_ALLOWLISTED")
    if doi is not None and (type(doi) is not str or DOI.fullmatch(doi) is None):
        raise FulltextHold("DOI_INVALID")


def fetch(pmcid: str) -> bytes:
    """One official pinned-TLS HTTPS GET, no redirect, retries or fallback."""
    _identity(pmcid)
    try:
        connection = PinnedHTTPS(resolve_public())
    except (OSError, ValueError):
        raise FulltextHold("FULLTEXT_NETWORK_UNAVAILABLE") from None
    try:
        connection.request(
            "GET", ENDPOINT + pmcid + "/fullTextXML",
            headers={"Host": HOST, "Accept": "application/xml",
                     "Accept-Encoding": "identity", "Connection": "close",
                     "User-Agent": "HermesResearchScout-FulltextAvailability/0.1"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise FulltextHold("FULLTEXT_NOT_AVAILABLE")
        mime = response.getheader("Content-Type", "").lower().split(";", 1)[0].strip()
        if mime not in ("application/xml", "text/xml"):
            raise FulltextHold("FULLTEXT_TYPE_INVALID")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise FulltextHold("FULLTEXT_ENCODING_INVALID")
        length = response.getheader("Content-Length")
        if length and (not length.isascii() or not length.isdigit()
                       or int(length) > MAX_XML):
            raise FulltextHold("FULLTEXT_SIZE_LIMIT")
        raw = response.read(MAX_XML + 1)
        if not raw or len(raw) > MAX_XML:
            raise FulltextHold("FULLTEXT_SIZE_LIMIT")
        return raw
    except (OSError, TimeoutError, http.client.HTTPException):
        raise FulltextHold("FULLTEXT_NETWORK_UNAVAILABLE") from None
    finally:
        connection.close()


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def inspect(pmcid: str, raw: bytes, *, expected_doi: str | None = None) -> dict:
    """Validate primary full-text *identity*, not claims, and emit no text."""
    _identity(pmcid, expected_doi)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_XML:
        raise FulltextHold("FULLTEXT_SIZE_LIMIT")
    safe_xml = xml_without_external_doctype(raw)
    try:
        root = ET.fromstring(safe_xml)
    except ET.ParseError:
        raise FulltextHold("FULLTEXT_XML_INVALID") from None
    if _local(root.tag) != "article":
        raise FulltextHold("FULLTEXT_JATS_REQUIRED")
    nodes = 0
    ids = {}
    body, license_present = False, False
    for elem in root.iter():
        nodes += 1
        if nodes > MAX_NODES:
            raise FulltextHold("FULLTEXT_NODE_LIMIT")
        name = _local(elem.tag)
        if name == "article-id":
            key = elem.attrib.get("pub-id-type")
            if key in ("pmc", "pmcid", "doi"):
                val = (elem.text or "").strip()
                if key in ids:
                    raise FulltextHold("FULLTEXT_ID_DUPLICATE")
                ids[key] = val
        elif name == "body":
            body = True
        elif name == "license":
            license_present = True
    # JATS/PMC use both pub-id-type="pmcid" and legacy "pmc". Require
    # at least one and compare EVERY present variant against the requested
    # PMCID: conflicting aliases must never bypass the identity gate.
    pmc_values = [ids[key] for key in ("pmc", "pmcid") if key in ids]
    if not pmc_values or any(
        value.removeprefix("PMC") != pmcid.removeprefix("PMC")
        for value in pmc_values
    ):
        raise FulltextHold("FULLTEXT_PMCI_MISMATCH")
    if expected_doi is not None and ids.get("doi", "").casefold() != expected_doi.casefold():
        raise FulltextHold("FULLTEXT_DOI_MISMATCH")
    if not body:
        raise FulltextHold("FULLTEXT_BODY_MISSING")
    # A JATS <license> marker alone never proves the right to republish.
    # A content inspector/human must independently check license, scientific
    # methods, retractions, and every exact claim before an article can exist.
    return {
        "source": "europe_pmc_fulltext_xml",
        "source_identity": pmcid,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "full_text_available": True,
        "license_marker_present": license_present,
        "license_reuse_verified": False,
        "primary_claims_verified": False,
        "claim_source_matrix": [],
        "reviewer_attestation": None,
        "status": "NEEDS_CONTENT",
        "yfc_intake_payload": None,
        "hmac_submission_allowed": False,
        "automatic_publication": False,
        "model_calls": 0,
    }
