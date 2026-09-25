"""Pydantic request/response schemas."""
from __future__ import annotations

import datetime as dt
from typing import List, Optional, Union

from pydantic import BaseModel, Field


class RuleIn(BaseModel):
    seq: int = Field(ge=1, le=4294967295)
    prefix: str
    action: str = Field(pattern="^(permit|deny)$")
    ge: Optional[int] = Field(default=None, ge=0, le=128)
    le: Optional[int] = Field(default=None, ge=0, le=128)
    remark: str = ""


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    family: int = Field(default=4, ge=4, le=6)
    default_action: str = Field(default="deny", pattern="^(permit|deny)$")
    description: str = ""


class PolicyRulesIn(BaseModel):
    rules: List[RuleIn]
    default_action: Optional[str] = Field(default=None, pattern="^(permit|deny)$")


class SnapshotIn(BaseModel):
    label: str = ""
    created_by: str = "lab"


class ClassifyIn(BaseModel):
    prefix: str


class ProbesIn(BaseModel):
    probes: List[str]
    node: str = "a"
    install: bool = True


class DiffIn(BaseModel):
    old_snapshot_id: int
    new_snapshot_id: int


class ScenarioIn(BaseModel):
    name: str
    description: str = ""
    from_snapshot_id: Optional[int] = None
    to_snapshot_id: Optional[int] = None
    probes: List[str] = []


class NeighborIn(BaseModel):
    name: str
    ip: str
    family: int = 4
    asn: Optional[int] = None
    inbound_policy: Optional[str] = None
    outbound_policy: Optional[str] = None
    description: str = ""


class RibRouteIn(BaseModel):
    prefix: str
    next_hop: str


class RibImportIn(BaseModel):
    """One RIB collection batch.  `routes` accepts "PREFIX NEXT_HOP" strings
    or {"prefix", "next_hop"} objects; any illegal line fails the whole batch."""
    neighbor: Optional[str] = None
    neighbor_id: Optional[int] = None
    family: int = 4
    collected_at: dt.datetime
    source_version: str = Field(min_length=1, max_length=128)
    label: str = ""
    routes: List[Union[RibRouteIn, str]] = Field(min_length=1)


class ImpactTaskIn(BaseModel):
    rib_snapshot_id: int
    old_snapshot_id: int
    new_snapshot_id: int


class ImpactCVIn(BaseModel):
    node: str = "a"
    limit: int = Field(default=50, ge=1, le=500)
