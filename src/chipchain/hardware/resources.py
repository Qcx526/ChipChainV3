"""Typed, source-bound hardware resource catalog; no name-based inference."""
from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from chipchain.domain.common import Contract
from chipchain.firmware.static_ir import content_id


class ResourceKind(StrEnum):
    MMIO_REGISTER = "MMIO_REGISTER"
    MEMORY_REGION = "MEMORY_REGION"
    SYSTEM_REGISTER = "SYSTEM_REGISTER"
    CSR = "CSR"
    INTERRUPT = "INTERRUPT"
    EXCEPTION_INTERFACE = "EXCEPTION_INTERFACE"
    CACHE_TLB_RESOURCE = "CACHE_TLB_RESOURCE"
    BUS_RESOURCE = "BUS_RESOURCE"
    DEVICE_STATE = "DEVICE_STATE"
    OTHER = "OTHER"


class HardwareResource(Contract):
    resource_id: str
    kind: ResourceKind
    architecture: Literal["arm", "riscv", "powerpc"]
    name: str
    address_start: int | None = Field(default=None, ge=0)
    address_end: int | None = Field(default=None, ge=0)
    register_identity: str | None = None
    width_bits: int | None = Field(default=None, gt=0)
    access: tuple[Literal["read", "write", "execute"], ...] = ()
    source_id: str
    scope: str

    @model_validator(mode="after")
    def identity(self):
        if (self.address_start is None) != (self.address_end is None):
            raise ValueError("Resource address range requires both endpoints")
        if self.address_start is not None and self.address_start > self.address_end:
            raise ValueError("Resource address range reversed")
        if self.kind in {ResourceKind.MMIO_REGISTER, ResourceKind.MEMORY_REGION} and self.address_start is None:
            raise ValueError("Addressed resource lacks address range")
        if self.kind in {ResourceKind.SYSTEM_REGISTER, ResourceKind.CSR} and not self.register_identity:
            raise ValueError("Register resource lacks objective identity")
        if self.resource_id != content_id("hwresource", self.model_dump(mode="json", exclude={"resource_id"})):
            raise ValueError("Hardware resource identity mismatch")
        return self


def build_resource(**fields) -> HardwareResource:
    fields["kind"] = ResourceKind(fields["kind"])
    normalized = HardwareResource.model_construct(resource_id="", **fields).model_dump(mode="json", exclude={"resource_id"})
    return HardwareResource.model_validate({**normalized, "resource_id": content_id("hwresource", normalized)})


class HardwareResourceCatalog(Contract):
    schema_version: Literal["hardware-resource-catalog/v1"] = "hardware-resource-catalog/v1"
    catalog_id: str
    architecture: Literal["arm", "riscv", "powerpc"]
    source_id: str
    scope: str
    resources: tuple[HardwareResource, ...]

    @model_validator(mode="after")
    def identity(self):
        if any(r.architecture != self.architecture for r in self.resources):
            raise ValueError("Catalog architecture conflict")
        if len({r.resource_id for r in self.resources}) != len(self.resources):
            raise ValueError("Duplicate resource")
        if self.catalog_id != content_id("hwcatalog", self.model_dump(mode="json", exclude={"catalog_id"})):
            raise ValueError("Hardware catalog identity mismatch")
        return self


def build_catalog(*, architecture: str, source_id: str, scope: str,
                  resources: tuple[HardwareResource, ...]) -> HardwareResourceCatalog:
    fields = {"schema_version": "hardware-resource-catalog/v1", "architecture": architecture,
              "source_id": source_id, "scope": scope,
              "resources": tuple(sorted(resources, key=lambda r: r.resource_id))}
    return HardwareResourceCatalog.model_validate({**fields, "catalog_id": content_id("hwcatalog", fields)})
