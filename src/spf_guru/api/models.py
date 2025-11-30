"""Pydantic models for API request/response schemas."""

from typing import List, Optional

from pydantic import BaseModel, Field


class DNSRecord(BaseModel):
    """DNS record response."""

    qname: str
    qtype: str
    content: str
    ttl: int
    auth: bool = True


class DNSLookupResponse(BaseModel):
    """Response from DNS lookup endpoint."""

    result: List[DNSRecord] = Field(default_factory=list)
    log: Optional[str] = None
