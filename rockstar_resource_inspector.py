#!/usr/bin/env python3
"""Read-only inspector for Rockstar RAGE resource/archive headers.

The parser is intentionally conservative. It prints metadata from known header
surfaces and validates every offset/length before reading.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import shutil
import struct
import sys
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


RSC7_MAGIC = b"RSC7"
RSC8_MAGIC = b"RSC8"
RPF7_MAGIC = b"RPF7"
RPF8_MAGIC = b"8FPR"

RPF_ENCRYPTION = {
    0x00000000: "NONE",
    0x4E45504F: "OPEN",
    0x0FFFFFF9: "AES",
    0x0FEFFFFF: "NG",
}

RESOURCE_EXTENSIONS = {
    ".ydd": "Drawable dictionary",
    ".ydr": "Drawable",
    ".yft": "Fragment",
    ".ytd": "Texture dictionary",
    ".ybn": "Bounds/collision",
    ".yld": "Cloth dictionary",
    ".ypt": "Particle effects",
    ".ymap": "Map data",
    ".ytyp": "Archetype/type data",
    ".ysc": "Script",
}


def joaat(text: str) -> int:
    value = 0
    for byte in text.lower().encode("utf-8"):
        value = (value + byte) & 0xFFFFFFFF
        value = (value + ((value << 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
        value ^= value >> 6
    value = (value + ((value << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    value ^= value >> 11
    value = (value + ((value << 15) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return value & 0xFFFFFFFF


def png_dimensions(data: bytes) -> tuple[int, int] | None:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", data[16:24])

DEFAULT_FIXTURE_PATH = Path("tests/fixtures/sample_drawable_3_models.ydr")
DEFAULT_MASK_XML_PATH = Path(
    r"C:\Users\zlinz\OneDrive\Desktop\RDR2 Skinning\build\rdr2_mask_export\p_humanskinmask01x.ydr.xml"
)
DEFAULT_LML_MASK_PACKAGE_PATH = Path(r"E:\Red Dead Redemption 2\lml\HumanSkinningMask")


class ParseError(ValueError):
    """Raised when a file cannot be parsed safely."""


@dataclass
class Issue:
    severity: str
    message: str


@dataclass
class ParseTraceEvent:
    label: str
    message: str
    offset: int | None = None
    length: int | None = None


@dataclass
class HexWindow:
    label: str
    offset: int
    length: int
    hex: str
    ascii: str


@dataclass
class PageFlags:
    raw_hex: str
    version_nibble: int
    base_shift: int
    base_size: int
    page_units: int
    decoded_size: int


@dataclass
class Rsc7Header:
    magic: str
    version: int
    system_flags: PageFlags
    graphics_flags: PageFlags
    payload_offset: int = 16
    payload_size: int = 0
    decoded_total_size: int = 0


@dataclass
class Rsc8Header:
    magic: str
    word1: int
    word2: int
    word3: int
    payload_offset: int = 16
    payload_size: int = 0
    legacy_version: int | None = None
    system_flags: PageFlags | None = None
    graphics_flags: PageFlags | None = None
    interpretation: str = "raw-rsc8"

    @property
    def word1_hex(self) -> str:
        return f"0x{self.word1:08X}"

    @property
    def word2_hex(self) -> str:
        return f"0x{self.word2:08X}"

    @property
    def word3_hex(self) -> str:
        return f"0x{self.word3:08X}"

    @property
    def decoded_total_size(self) -> int | None:
        if self.system_flags is None or self.graphics_flags is None:
            return None
        return self.system_flags.decoded_size + self.graphics_flags.decoded_size


@dataclass(frozen=True)
class ResourceSection:
    name: str
    virtual_base: int
    payload_offset: int
    size: int

    @property
    def virtual_end(self) -> int:
        return self.virtual_base + self.size

    @property
    def payload_end(self) -> int:
        return self.payload_offset + self.size

    def contains_pointer(self, pointer: int) -> bool:
        return self.virtual_base <= pointer < self.virtual_end

    def pointer_to_payload_offset(self, pointer: int) -> int:
        return self.payload_offset + (pointer - self.virtual_base)


@dataclass(frozen=True)
class ResourceAddress:
    pointer: int
    section: str
    payload_offset: int

    @property
    def pointer_hex(self) -> str:
        return f"0x{self.pointer:016X}"


@dataclass
class ResourceLayout:
    system: ResourceSection
    graphics: ResourceSection

    def resolve(self, pointer: int) -> ResourceAddress | None:
        if pointer == 0:
            return None
        for section in (self.system, self.graphics):
            if section.contains_pointer(pointer):
                return ResourceAddress(
                    pointer=pointer,
                    section=section.name,
                    payload_offset=section.pointer_to_payload_offset(pointer),
                )
        return None


@dataclass
class ModelCounts:
    high: int = 0
    medium: int = 0
    low: int = 0
    very_low: int = 0

    @property
    def total(self) -> int:
        return self.high + self.medium + self.low + self.very_low

    def items(self) -> tuple[tuple[str, int], ...]:
        return (
            ("high", self.high),
            ("medium", self.medium),
            ("low", self.low),
            ("very_low", self.very_low),
        )


@dataclass
class DrawableModelListInfo:
    lod: str
    owner_field_offset: int
    pointer: int
    payload_offset: int | None
    pointer_array: int
    pointer_array_payload_offset: int | None
    count: int
    capacity: int
    model_pointers: list[int] = field(default_factory=list)
    is_duplicate_pointer: bool = False

    @property
    def pointer_hex(self) -> str:
        return f"0x{self.pointer:016X}"

    @property
    def pointer_array_hex(self) -> str:
        return f"0x{self.pointer_array:016X}"


@dataclass
class RpfEntry:
    index: int
    kind: str
    name: str
    name_offset: int
    size: int | None = None
    offset: int | None = None
    file_offset_bytes: int | None = None
    system_flags: PageFlags | None = None
    graphics_flags: PageFlags | None = None
    first_child_index: int | None = None
    child_count: int | None = None


@dataclass
class Rpf7Header:
    magic: str
    entry_count: int
    names_length: int
    encryption_value_hex: str
    encryption: str
    toc_offset: int
    toc_size: int
    entries: list[RpfEntry] = field(default_factory=list)


@dataclass
class SignatureHit:
    signature: str
    offset: int

    @property
    def offset_hex(self) -> str:
        return f"0x{self.offset:X}"


@dataclass
class TocRegionAnalysis:
    offset: int
    size: int
    entropy: float
    printable_ratio: float
    zero_ratio: float
    zlib_status: str
    raw_deflate_status: str
    entry16_plausible_ratio: float
    entry20_plausible_ratio: float

    @property
    def offset_hex(self) -> str:
        return f"0x{self.offset:X}"


@dataclass
class Rpf8Header:
    magic: str
    entry_count_guess: int
    toc_size_guess: int
    flags_raw_hex: str
    flags_low: int
    flags_high: int
    nested_rpf8_offsets: list[int] = field(default_factory=list)
    resource_signature_hits: list[SignatureHit] = field(default_factory=list)
    toc_regions: list[TocRegionAnalysis] = field(default_factory=list)
    toc_transform_guess: str = "unknown"
    toc_transform_evidence: list[str] = field(default_factory=list)


@dataclass
class Rpf8DecodedEntry:
    index: int
    kind: str
    name: str
    name_offset: int
    raw_hex: str
    size: int | None = None
    file_offset_bytes: int | None = None
    first_child_index: int | None = None
    child_count: int | None = None
    system_flags_hex: str | None = None
    graphics_flags_hex: str | None = None


@dataclass
class Rpf8TocDecodeReport:
    toc_path: str
    entry_count: int
    entry_size: int
    names_offset: int
    names_length: int
    entries: list[Rpf8DecodedEntry]
    warnings: list[str] = field(default_factory=list)


@dataclass
class Rsc8CorpusEntry:
    path: str
    extension: str
    file_size: int
    word1_hex: str
    word2_hex: str
    word3_hex: str
    word1_low16: int
    word1_high16: int
    word2_low16: int
    word2_high16: int
    word3_low16: int
    word3_high16: int
    payload_size: int
    payload_units_2048_floor: int
    word3_high16_matches_2048_floor: bool


@dataclass
class Rsc8CorpusReport:
    root: str
    entries: list[Rsc8CorpusEntry]
    observations: list[str] = field(default_factory=list)


@dataclass
class NativeYdrToolFinding:
    name: str
    path: str
    status: str
    reason: str


@dataclass
class NativeYdrToolReport:
    roots: list[str]
    findings: list[NativeYdrToolFinding]
    native_rdr2_ydr_writer_available: bool
    recommendation: str


@dataclass
class HeaderFieldAnnotation:
    offset: int
    length: int
    field: str
    native_hex: str
    generated_hex: str
    status: str
    note: str


@dataclass
class HeaderByteDiff:
    offset: int
    native_hex: str
    generated_hex: str
    same: bool
    label: str


@dataclass
class HeaderComparisonReport:
    native_path: str
    generated_path: str
    native_type: str | None
    generated_type: str | None
    native_format: str
    generated_format: str
    bytes_compared: int
    raw_native_hex: str
    raw_generated_hex: str
    raw_xor_hex: str
    annotations: list[HeaderFieldAnnotation]
    byte_diffs: list[HeaderByteDiff]
    warnings: list[str] = field(default_factory=list)


@dataclass
class ResourceLayoutMetadata:
    path: str
    format: str
    resource_type: str | None
    file_size: int
    payload_offset: int | None
    payload_size: int | None
    interpretation: str | None
    word1_hex: str | None
    word2_hex: str | None
    word3_hex: str | None
    system_size: int | None
    graphics_size: int | None
    decoded_total_size: int | None
    payload_encoding: str | None
    system_section: dict[str, Any] | None
    graphics_section: dict[str, Any] | None
    notes: list[str] = field(default_factory=list)


@dataclass
class PageSemanticAnnotation:
    file_role: str
    field: str
    offset: int
    raw_hex: str
    status: str
    decoded: dict[str, Any] | None
    note: str


@dataclass
class ControlledMutationResult:
    target: str
    mutation: str
    offset: int
    original_hex: str
    mutated_hex: str
    interpretation: str | None
    system_size: int | None
    graphics_size: int | None
    decoded_total_size: int | None
    outcome: str
    note: str


@dataclass
class ResourceLayoutComparisonReport:
    header: HeaderComparisonReport
    native_layout: ResourceLayoutMetadata
    generated_layout: ResourceLayoutMetadata
    page_semantics: list[PageSemanticAnnotation]
    mutations: list[ControlledMutationResult]
    warnings: list[str] = field(default_factory=list)


@dataclass
class RelocationEntry:
    source: str
    owner: str
    owner_type: str | None
    field: str
    offset: int | None
    offset_group: str
    target: str
    target_type: str | None
    pointer: str
    owner_section: str | None
    target_section: str | None
    page_crossing: bool
    confidence: str


@dataclass
class RelocationSummary:
    path: str
    source: str
    total: int
    exact_offsets: int
    inferred_offsets: int
    page_crossing: int
    by_section_pair: dict[str, int]
    by_owner_type: dict[str, int]
    by_target_type: dict[str, int]
    density_per_kb: dict[str, float]
    entries: list[RelocationEntry]
    warnings: list[str] = field(default_factory=list)


@dataclass
class RelocationComparisonReport:
    left: RelocationSummary
    right: RelocationSummary
    missing_in_right: list[RelocationEntry]
    extra_in_right: list[RelocationEntry]
    ordering_differences: list[str]
    section_pair_deltas: dict[str, int]
    warnings: list[str] = field(default_factory=list)


@dataclass
class PageDomainEntry:
    name: str
    type: str
    intended_domain: str
    actual_domain: str | None
    offset: int | None
    size: int | None
    alignment: int | None
    confidence: str
    note: str


@dataclass
class PageDomainReport:
    path: str
    entries: list[PageDomainEntry]
    warnings: list[str] = field(default_factory=list)


@dataclass
class MutationMatrixCell:
    variant: str
    field: str
    baseline: Any
    value: Any
    classification: str


@dataclass
class MutationMatrixReport:
    manifest_path: str
    baseline_variant: str
    cells: list[MutationMatrixCell]
    field_classifications: dict[str, str]
    warnings: list[str] = field(default_factory=list)


@dataclass
class NativeYdrCandidate:
    path: str
    file_size: int
    format: str
    resource_type: str | None
    header_interpretation: str | None
    drawable_models: int | None
    generated_by_project: bool
    suitability: str
    reason: str


@dataclass
class NativeYdrCandidateReport:
    roots: list[str]
    candidates: list[NativeYdrCandidate]
    best_candidates: list[NativeYdrCandidate]
    warnings: list[str] = field(default_factory=list)


@dataclass
class ByteRegionStats:
    label: str
    offset: int
    length: int
    entropy: float
    zero_ratio: float
    printable_ratio: float
    unique_byte_count: int
    raw_prefix: str
    classification: str


@dataclass
class NativeReferenceField:
    offset: int
    length: int
    field: str
    raw_hex: str
    value: str
    confidence: str
    note: str


@dataclass
class TransformProbe:
    name: str
    status: str
    output_size: int | None = None
    note: str = ""


@dataclass
class NativeRsc8ReferenceReport:
    path: str
    file_size: int
    resource_type: str
    header_fields: list[NativeReferenceField]
    region_stats: list[ByteRegionStats]
    transform_probes: list[TransformProbe]
    oodle_probes: list[TransformProbe]
    pointer_scan_hits: list[str]
    string_hits: list[str]
    inferred_page_notes: list[str]
    structural_status: str
    warnings: list[str] = field(default_factory=list)


@dataclass
class LmlStageReport:
    package_path: str
    stream_path: str
    ydr_path: str
    install_xml_path: str
    install_xml_backup: str | None
    streaming_entries: list[str]
    lml_visible: bool
    native_rdr2_valid: bool
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class YdrInfo:
    payload_encoding: str
    resource_layout: ResourceLayout
    model_lists: list[DrawableModelListInfo]
    resource_map: "ResourceMap | None" = None

    @property
    def drawable_models(self) -> int:
        return sum(model_list.count for model_list in self.model_lists)

    @property
    def drawable_models_high(self) -> int:
        return self.model_count_for("high")

    @property
    def drawable_models_medium(self) -> int:
        return self.model_count_for("medium")

    @property
    def drawable_models_low(self) -> int:
        return self.model_count_for("low")

    @property
    def drawable_models_very_low(self) -> int:
        return self.model_count_for("very_low")

    @property
    def drawable_model_list_pointers(self) -> dict[str, str]:
        return {model_list.lod: model_list.pointer_hex for model_list in self.model_lists}

    def model_count_for(self, lod: str) -> int:
        return sum(model_list.count for model_list in self.model_lists if model_list.lod == lod)


@dataclass
class Inspection:
    path: str
    file_name: str
    file_size: int
    extension: str
    guessed_resource_type: str | None
    format: str
    header: Rsc7Header | Rsc8Header | Rpf7Header | Rpf8Header | None
    ydr: YdrInfo | None = None
    issues: list[Issue] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    trace: list[ParseTraceEvent] = field(default_factory=list)
    hex_windows: list[HexWindow] = field(default_factory=list)


@dataclass
class BoundaryValidation:
    pointer: str
    label: str
    status: str
    section: str | None = None
    payload_offset: int | None = None
    required_length: int | None = None
    message: str = ""


@dataclass
class ResourceMapNode:
    id: str
    label: str
    type: str
    pointer: str
    section: str | None
    payload_offset: int | None
    length: int | None = None


@dataclass
class ResourceMapEdge:
    source: str
    target: str
    field: str
    pointer: str
    status: str


@dataclass
class ResourceMap:
    root: str
    nodes: list[ResourceMapNode] = field(default_factory=list)
    edges: list[ResourceMapEdge] = field(default_factory=list)
    boundary_validations: list[BoundaryValidation] = field(default_factory=list)


@dataclass
class VertexRowXml:
    position: tuple[float, float, float]
    normal: tuple[float, float, float, float]
    tangent: tuple[float, float, float, float]
    color: tuple[int, int, int, int]
    uv: tuple[float, float]


@dataclass
class VertexElementBinding:
    semantic: str
    component_type: str
    component_count: int
    bytes_per_component: int
    offset: int
    size: int


@dataclass
class VertexDeclarationBinding:
    semantics: str
    formats: list[int]
    non_interleaved: bool
    stride: int
    elements: list[VertexElementBinding]


@dataclass
class VertexBufferXml:
    layout_semantics: str
    formats: list[int]
    non_interleaved: bool
    vertex_count: int
    vertices: list[VertexRowXml] = field(default_factory=list)


@dataclass
class IndexBufferXml:
    index_count: int
    triangle_count: int
    max_index: int | None
    indices: list[int] = field(default_factory=list)

    @property
    def required_index_size_bits(self) -> int:
        return 32 if self.max_index is not None and self.max_index > 0xFFFF else 16

    @property
    def is_triangle_aligned(self) -> bool:
        return self.index_count % 3 == 0


@dataclass
class IndexPackingInfo:
    index_size_bits: int
    index_size_bytes: int
    index_count: int
    triangle_count: int
    max_index: int | None
    data_size: int
    alignment: int
    endian: str


@dataclass
class DrawableGeometryXml:
    shader_id: int
    shader_name: str | None
    vertex_buffer: VertexBufferXml
    index_buffer: IndexBufferXml


@dataclass
class DrawableModelXml:
    lod: str
    flags: int
    has_skin: bool
    bone_index: int
    bones_count: int
    geometries: list[DrawableGeometryXml]


@dataclass
class ShaderGroupXml:
    shaders: list["ShaderXml"]
    textures: list["TextureXml"]

    @property
    def shader_names(self) -> list[str]:
        return [shader.name for shader in self.shaders]

    @property
    def texture_names(self) -> list[str]:
        return [texture.name for texture in self.textures]


@dataclass
class TextureXml:
    name: str
    flags: int


@dataclass
class ShaderParameterXml:
    name: str
    type: str
    index: int | None = None
    texture: str | None = None
    sampler: int | None = None
    flags: int | None = None
    buffer: int | None = None
    offset: int | None = None
    length: int | None = None
    values: tuple[float, ...] = ()


@dataclass
class ShaderParametersXml:
    buffer_sizes: list[int] = field(default_factory=list)
    items: list[ShaderParameterXml] = field(default_factory=list)


@dataclass
class ShaderXml:
    name: str
    draw_bucket: int = 0
    draw_bucket_flag: bool = False
    parameters: ShaderParametersXml = field(default_factory=ShaderParametersXml)


@dataclass
class DrawableXml:
    name: str
    hash_name: str
    shader_group: ShaderGroupXml
    models: list[DrawableModelXml]
    source_xml_path: Path | None = None

    @property
    def model_count(self) -> int:
        return len(self.models)

    @property
    def geometry_count(self) -> int:
        return sum(len(model.geometries) for model in self.models)

    @property
    def vertex_count(self) -> int:
        return sum(geometry.vertex_buffer.vertex_count for model in self.models for geometry in model.geometries)

    @property
    def index_count(self) -> int:
        return sum(geometry.index_buffer.index_count for model in self.models for geometry in model.geometries)

    @property
    def primary_shader(self) -> str | None:
        return self.shader_group.shaders[0].name if self.shader_group.shaders else None

    @property
    def primary_texture(self) -> str | None:
        return self.shader_group.textures[0].name if self.shader_group.textures else None

    @property
    def primary_vertex_layout(self) -> str | None:
        for model in self.models:
            for geometry in model.geometries:
                return geometry.vertex_buffer.layout_semantics
        return None


@dataclass
class BinaryObjectRecord:
    name: str
    type: str
    section: str
    offset: int
    pointer: int
    size: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def pointer_hex(self) -> str:
        return f"0x{self.pointer:016X}"


@dataclass
class BinaryFixupRecord:
    owner: str
    field: str
    offset: int
    target: str
    pointer: int

    @property
    def pointer_hex(self) -> str:
        return f"0x{self.pointer:016X}"


@dataclass
class BinaryWriteReport:
    output_path: str
    version: int
    system_size: int
    graphics_size: int
    objects: list[BinaryObjectRecord]
    fixups: list[BinaryFixupRecord]
    warnings: list[str]


@dataclass
class StructureFieldSnapshot:
    structure: str
    label: str
    offset: int
    size: int
    value: str
    meaning: str
    confidence: str


@dataclass
class StructureNodeSnapshot:
    label: str
    type: str
    pointer: str
    section: str | None
    payload_offset: int | None
    length: int | None
    fields: list[StructureFieldSnapshot] = field(default_factory=list)
    unknown_nonzero_bytes: int = 0
    raw_prefix: str = ""


@dataclass
class YdrStructureSnapshot:
    path: str
    version: int
    system_size: int
    graphics_size: int
    drawable_models: int
    boundary_valid: int
    boundary_null: int
    boundary_invalid: int
    nodes: list[StructureNodeSnapshot]


@dataclass
class StructureComparisonRow:
    structure: str
    label: str
    known_good: str
    candidate: str
    status: str


@dataclass
class YdrStructureComparison:
    known_good: YdrStructureSnapshot
    candidate: YdrStructureSnapshot
    rows: list[StructureComparisonRow]
    missing_in_candidate: list[str]
    extra_in_candidate: list[str]


class SectionBuffer:
    def __init__(self, name: str, virtual_base: int) -> None:
        self.name = name
        self.virtual_base = virtual_base
        self.data = bytearray()

    def allocate(self, size: int, alignment: int = 16) -> int:
        offset = align(len(self.data), alignment)
        if offset > len(self.data):
            self.data.extend(b"\x00" * (offset - len(self.data)))
        self.data.extend(b"\x00" * size)
        return offset

    def pointer(self, offset: int) -> int:
        return self.virtual_base + offset

    def write(self, offset: int, payload: bytes) -> None:
        self.data[offset : offset + len(payload)] = payload

    def pack_into(self, fmt: str, offset: int, *values: Any) -> None:
        struct.pack_into(fmt, self.data, offset, *values)

    def aligned_bytes(self, alignment: int = 0x2000) -> bytes:
        size = align(len(self.data), alignment)
        return bytes(self.data + bytearray(size - len(self.data)))


class RageBinaryStructureWriter:
    """First-pass RAGE/RDR2 structure writer.

    The fixed headers follow CodeWalker-observed field order and block sizes.
    Vertex bytes are currently emitted as deterministic raw float/color data for
    the parsed XML rows; format-specific RDR2 compression is a later stage.
    """

    SHADER_GROUP_SIZE = 64
    TEXTURE_DICTIONARY_SIZE = 64
    SHADER_FX_SIZE = 48
    DRAWABLE_BASE_SIZE = 168
    DRAWABLE_MODEL_BASE_SIZE = 48
    DRAWABLE_GEOMETRY_SIZE = 0x98
    VERTEX_BUFFER_SIZE = 128
    INDEX_BUFFER_SIZE = 96
    PNXCT_STRIDE = 56
    SHADER_PARAMETER_ENTRY_SIZE = 64

    def __init__(self, version: int = 165, endian: str = "little") -> None:
        self.version = version
        self.endian = endian
        self.struct_endian = "<" if endian == "little" else ">"
        self.system = SectionBuffer("system", 0x50000000)
        self.graphics = SectionBuffer("graphics", 0x60000000)
        self.objects: list[BinaryObjectRecord] = []
        self.fixups: list[BinaryFixupRecord] = []
        self.warnings: list[str] = []

    def record(
        self,
        name: str,
        type_name: str,
        section: SectionBuffer,
        offset: int,
        size: int,
        metadata: dict[str, Any] | None = None,
    ) -> BinaryObjectRecord:
        item = BinaryObjectRecord(
            name=name,
            type=type_name,
            section=section.name,
            offset=offset,
            pointer=section.pointer(offset),
            size=size,
            metadata=metadata or {},
        )
        self.objects.append(item)
        return item

    def fixup(self, owner: str, field: str, offset: int, target: BinaryObjectRecord) -> None:
        self.fixups.append(BinaryFixupRecord(owner, field, offset, target.name, target.pointer))

    @staticmethod
    def clamp_u8(value: int) -> int:
        return max(0, min(255, value))

    def pack_floats(self, values: tuple[float, ...]) -> bytes:
        return struct.pack(f"{self.struct_endian}{len(values)}f", *values)

    def pack_color(self, values: tuple[int, int, int, int]) -> bytes:
        return bytes(self.clamp_u8(value) for value in values)

    def pack_pnxct_vertex(self, vertex: VertexRowXml) -> bytes:
        return b"".join(
            (
                self.pack_floats(vertex.position),
                self.pack_floats(vertex.normal),
                self.pack_floats(vertex.tangent),
                self.pack_color(vertex.color),
                self.pack_floats(vertex.uv),
            )
        )

    def bind_vertex_declaration(self, vertex_buffer: VertexBufferXml) -> VertexDeclarationBinding:
        if vertex_buffer.layout_semantics != "PNXCT":
            self.warnings.append(
                f"vertex layout {vertex_buffer.layout_semantics!r} has no confirmed declaration binding"
            )
            return VertexDeclarationBinding(
                semantics=vertex_buffer.layout_semantics,
                formats=vertex_buffer.formats,
                non_interleaved=vertex_buffer.non_interleaved,
                stride=self.PNXCT_STRIDE,
                elements=[],
            )
        sizes = {
            "P": ("float32", 3, 4, 12),
            "N": ("float32", 4, 4, 16),
            "X": ("float32", 4, 4, 16),
            "C": ("uint8", 4, 1, 4),
            "T": ("float32", 2, 4, 8),
        }
        elements: list[VertexElementBinding] = []
        offset = 0
        for semantic in "PNXCT":
            component_type, component_count, bytes_per_component, size = sizes[semantic]
            elements.append(
                VertexElementBinding(
                    semantic=semantic,
                    component_type=component_type,
                    component_count=component_count,
                    bytes_per_component=bytes_per_component,
                    offset=offset,
                    size=size,
                )
            )
            offset += size
        return VertexDeclarationBinding(
            semantics=vertex_buffer.layout_semantics,
            formats=vertex_buffer.formats,
            non_interleaved=vertex_buffer.non_interleaved,
            stride=self.PNXCT_STRIDE,
            elements=elements,
        )

    @staticmethod
    def vertex_declaration_metadata(binding: VertexDeclarationBinding) -> dict[str, Any]:
        return {
            "vertex_layout": binding.semantics,
            "vertex_formats": binding.formats,
            "non_interleaved": binding.non_interleaved,
            "stride": binding.stride,
            "elements": [asdict(element) for element in binding.elements],
        }

    def encode_pnxct_interleaved(self, vertices: list[VertexRowXml]) -> bytes:
        return b"".join(self.pack_pnxct_vertex(vertex) for vertex in vertices)

    def encode_pnxct_non_interleaved(self, vertices: list[VertexRowXml]) -> bytes:
        return b"".join(
            (
                b"".join(self.pack_floats(vertex.position) for vertex in vertices),
                b"".join(self.pack_floats(vertex.normal) for vertex in vertices),
                b"".join(self.pack_floats(vertex.tangent) for vertex in vertices),
                b"".join(self.pack_color(vertex.color) for vertex in vertices),
                b"".join(self.pack_floats(vertex.uv) for vertex in vertices),
            )
        )

    def encode_vertex_data(self, geometry: DrawableGeometryXml) -> tuple[bytes, int]:
        binding = self.bind_vertex_declaration(geometry.vertex_buffer)
        if geometry.vertex_buffer.layout_semantics != "PNXCT":
            self.warnings.append(
                f"vertex layout {geometry.vertex_buffer.layout_semantics!r} uses placeholder zeroed vertex bytes"
            )
            stride = binding.stride
            return b"\x00" * (geometry.vertex_buffer.vertex_count * stride), stride
        stride = binding.stride
        if geometry.vertex_buffer.non_interleaved:
            data = self.encode_pnxct_non_interleaved(geometry.vertex_buffer.vertices)
            self.warnings.append("PNXCT vertex data packed as non-interleaved P/N/X/C/T attribute planes")
        else:
            data = self.encode_pnxct_interleaved(geometry.vertex_buffer.vertices)
            self.warnings.append("PNXCT vertex data packed as interleaved P/N/X/C/T records")
        expected = geometry.vertex_buffer.vertex_count * stride
        if len(data) != expected:
            raise ParseError(f"PNXCT vertex data length mismatch: got {len(data)}, expected {expected}")
        return data, stride

    def choose_index_packing(self, geometry: DrawableGeometryXml) -> IndexPackingInfo:
        indices = geometry.index_buffer.indices
        if len(indices) != geometry.index_buffer.index_count:
            raise ParseError(
                f"index count mismatch: header={geometry.index_buffer.index_count}, parsed={len(indices)}"
            )
        if any(index < 0 for index in indices):
            raise ParseError("index buffer contains negative indices")
        actual_max = max(indices) if indices else None
        if actual_max is not None and actual_max > 0xFFFFFFFF:
            raise ParseError(f"index buffer contains value above uint32 range: {actual_max}")
        if geometry.index_buffer.max_index is not None and actual_max != geometry.index_buffer.max_index:
            self.warnings.append(
                f"index max metadata {geometry.index_buffer.max_index} differs from parsed max {actual_max}"
            )
        if not geometry.index_buffer.is_triangle_aligned:
            self.warnings.append(
                f"index count {geometry.index_buffer.index_count} is not divisible by 3; triangle list may be malformed"
            )
        inferred_triangles = geometry.index_buffer.index_count // 3
        if geometry.index_buffer.triangle_count != inferred_triangles:
            self.warnings.append(
                f"triangle count metadata {geometry.index_buffer.triangle_count} differs from index_count/3 {inferred_triangles}"
            )
        if actual_max is not None and actual_max >= geometry.vertex_buffer.vertex_count:
            self.warnings.append(
                f"index buffer references vertex {actual_max}, but vertex count is {geometry.vertex_buffer.vertex_count}"
            )
        index_size_bits = 32 if actual_max is not None and actual_max > 0xFFFF else 16
        index_size_bytes = index_size_bits // 8
        index_count = geometry.index_buffer.index_count
        return IndexPackingInfo(
            index_size_bits=index_size_bits,
            index_size_bytes=index_size_bytes,
            index_count=index_count,
            triangle_count=geometry.index_buffer.triangle_count,
            max_index=actual_max,
            data_size=index_count * index_size_bytes,
            alignment=16,
            endian=self.endian,
        )

    def encode_index_data(self, geometry: DrawableGeometryXml) -> tuple[bytes, IndexPackingInfo]:
        packing = self.choose_index_packing(geometry)
        element = "I" if packing.index_size_bits == 32 else "H"
        data = struct.pack(
            f"{self.struct_endian}{packing.index_count}{element}",
            *geometry.index_buffer.indices,
        )
        if len(data) != packing.data_size:
            raise ParseError(f"index data length mismatch: got {len(data)}, expected {packing.data_size}")
        return data, packing

    def write_vertex_data(self, name: str, geometry: DrawableGeometryXml) -> tuple[BinaryObjectRecord, int]:
        data, stride = self.encode_vertex_data(geometry)
        offset = self.graphics.allocate(len(data), 16)
        self.graphics.write(offset, data)
        binding = self.bind_vertex_declaration(geometry.vertex_buffer)
        metadata = self.vertex_declaration_metadata(binding)
        metadata.update({"vertex_count": geometry.vertex_buffer.vertex_count, "data_size": len(data), "alignment": 16})
        return self.record(name, "VertexData", self.graphics, offset, len(data), metadata), stride

    def write_index_data(self, name: str, geometry: DrawableGeometryXml) -> tuple[BinaryObjectRecord, IndexPackingInfo]:
        data, packing = self.encode_index_data(geometry)
        offset = self.graphics.allocate(len(data), packing.alignment)
        self.graphics.write(offset, data)
        metadata = {
            "index_size_bits": packing.index_size_bits,
            "index_size_bytes": packing.index_size_bytes,
            "index_count": packing.index_count,
            "triangle_count": packing.triangle_count,
            "max_index": packing.max_index,
            "alignment": packing.alignment,
            "endian": packing.endian,
            "data_size": packing.data_size,
        }
        return self.record(name, "IndexData", self.graphics, offset, len(data), metadata), packing

    def write_vertex_buffer(self, name: str, geometry: DrawableGeometryXml, vertex_data: BinaryObjectRecord, stride: int) -> BinaryObjectRecord:
        offset = self.system.allocate(self.VERTEX_BUFFER_SIZE, 16)
        self.system.pack_into(
            "<IIHHIQII" + ("Q" * 12),
            offset,
            1080153080,
            1,
            stride,
            0,
            0,
            vertex_data.pointer,
            geometry.vertex_buffer.vertex_count,
            0,
            vertex_data.pointer,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        binding = self.bind_vertex_declaration(geometry.vertex_buffer)
        metadata = self.vertex_declaration_metadata(binding)
        metadata.update({"vertex_count": geometry.vertex_buffer.vertex_count, "data_pointer": vertex_data.pointer_hex})
        item = self.record(name, "VertexBuffer", self.system, offset, self.VERTEX_BUFFER_SIZE, metadata)
        self.fixup(item.name, "DataPointer1", offset + 0x10, vertex_data)
        self.fixup(item.name, "DataPointer2", offset + 0x20, vertex_data)
        return item

    def write_index_buffer(
        self,
        name: str,
        geometry: DrawableGeometryXml,
        index_data: BinaryObjectRecord,
        packing: IndexPackingInfo,
    ) -> BinaryObjectRecord:
        offset = self.system.allocate(self.INDEX_BUFFER_SIZE, 16)
        self.system.pack_into(
            "<III I Q Q Q Q Q Q Q Q Q Q",
            offset,
            1080152408,
            1,
            geometry.index_buffer.index_count,
            0,
            index_data.pointer,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        metadata = {
            "index_size_bits": packing.index_size_bits,
            "index_size_bytes": packing.index_size_bytes,
            "index_count": packing.index_count,
            "triangle_count": packing.triangle_count,
            "max_index": packing.max_index,
            "data_pointer": index_data.pointer_hex,
            "data_size": packing.data_size,
        }
        item = self.record(name, "IndexBuffer", self.system, offset, self.INDEX_BUFFER_SIZE, metadata)
        self.fixup(item.name, "IndicesPointer", offset + 0x10, index_data)
        return item

    def write_geometry(
        self,
        name: str,
        geometry: DrawableGeometryXml,
        vertex_buffer: BinaryObjectRecord,
        index_buffer: BinaryObjectRecord,
        vertex_data: BinaryObjectRecord,
        stride: int,
    ) -> BinaryObjectRecord:
        offset = self.system.allocate(self.DRAWABLE_GEOMETRY_SIZE, 16)
        self.system.pack_into("<IIQQQ", offset, 1080133528, 1, 0, 0, vertex_buffer.pointer)
        self.system.pack_into("<Q", offset + 0x38, index_buffer.pointer)
        self.system.pack_into(
            "<IIHHI",
            offset + 0x58,
            geometry.index_buffer.index_count,
            geometry.index_buffer.triangle_count,
            min(geometry.vertex_buffer.vertex_count, 0xFFFF),
            3,
            0,
        )
        self.system.pack_into("<QHHI", offset + 0x68, 0, stride, 0, 0)
        self.system.pack_into("<Q", offset + 0x78, vertex_data.pointer)
        item = self.record(name, "DrawableGeometry", self.system, offset, self.DRAWABLE_GEOMETRY_SIZE)
        self.fixup(item.name, "VertexBufferPointer", offset + 0x18, vertex_buffer)
        self.fixup(item.name, "IndexBufferPointer", offset + 0x38, index_buffer)
        self.fixup(item.name, "VertexDataPointer", offset + 0x78, vertex_data)
        return item

    def write_model(self, name: str, model: DrawableModelXml, geometry_records: list[BinaryObjectRecord]) -> BinaryObjectRecord:
        count = len(geometry_records)
        shader_mapping_size = align(count * 2, 16)
        geometry_pointer_size = align(count * 8, 16)
        bounds_count = count + (1 if count > 1 else 0)
        bounds_size = bounds_count * 32
        total_size = self.DRAWABLE_MODEL_BASE_SIZE + shader_mapping_size + geometry_pointer_size + bounds_size
        offset = self.system.allocate(total_size, 16)
        shader_mapping_offset = offset + self.DRAWABLE_MODEL_BASE_SIZE
        geometry_pointer_offset = shader_mapping_offset + shader_mapping_size
        bounds_offset = geometry_pointer_offset + geometry_pointer_size
        self.system.pack_into(
            "<IIQHHIQQIHH",
            offset,
            1080101528,
            1,
            self.system.pointer(geometry_pointer_offset),
            count,
            count,
            0,
            self.system.pointer(bounds_offset),
            self.system.pointer(shader_mapping_offset),
            0,
            model.flags & 0xFFFF,
            count,
        )
        for index, geometry in enumerate(model.geometries):
            self.system.pack_into("<H", shader_mapping_offset + index * 2, geometry.shader_id)
        for index, geometry_record in enumerate(geometry_records):
            self.system.pack_into("<Q", geometry_pointer_offset + index * 8, geometry_record.pointer)
        item = self.record(name, "DrawableModel", self.system, offset, total_size)
        self.fixups.append(BinaryFixupRecord(item.name, "ShaderMappingPointer", offset + 0x20, "shader mapping inline", self.system.pointer(shader_mapping_offset)))
        self.fixups.append(BinaryFixupRecord(item.name, "GeometriesPointer", offset + 0x08, "geometry pointer array", self.system.pointer(geometry_pointer_offset)))
        self.fixups.append(BinaryFixupRecord(item.name, "BoundsPointer", offset + 0x18, "bounds inline", self.system.pointer(bounds_offset)))
        return item

    def serialize_shader_parameter(self, parameter: ShaderParameterXml) -> bytes:
        type_ids = {"Texture": 1, "Sampler": 2, "CBuffer": 3}
        values = list(parameter.values[:4]) + [0.0] * (4 - len(parameter.values[:4]))
        return struct.pack(
            f"{self.struct_endian}IIIIIIIIffffII",
            joaat(parameter.name),
            type_ids.get(parameter.type, 0),
            parameter.index if parameter.index is not None else 0xFFFFFFFF,
            joaat(parameter.texture) if parameter.texture else 0,
            parameter.sampler if parameter.sampler is not None else 0xFFFFFFFF,
            parameter.flags if parameter.flags is not None else 0,
            parameter.buffer if parameter.buffer is not None else 0xFFFFFFFF,
            parameter.offset if parameter.offset is not None else 0,
            values[0],
            values[1],
            values[2],
            values[3],
            parameter.length if parameter.length is not None else 0,
            0,
        )

    def write_shader_parameter_table(self, name: str, shader: ShaderXml) -> BinaryObjectRecord:
        entries = b"".join(self.serialize_shader_parameter(parameter) for parameter in shader.parameters.items)
        cbuffer_payload = b"".join(struct.pack(f"{self.struct_endian}I", size) for size in shader.parameters.buffer_sizes)
        header_size = 32
        payload = struct.pack(
            f"{self.struct_endian}IIIIIIII",
            0x42545053,
            1,
            len(shader.parameters.items),
            len(shader.parameters.buffer_sizes),
            header_size,
            header_size + len(entries),
            len(entries),
            len(cbuffer_payload),
        ) + entries + cbuffer_payload
        offset = self.system.allocate(len(payload), 16)
        self.system.write(offset, payload)
        metadata = {
            "shader": shader.name,
            "parameter_count": len(shader.parameters.items),
            "texture_parameters": sum(1 for item in shader.parameters.items if item.type == "Texture"),
            "sampler_parameters": sum(1 for item in shader.parameters.items if item.type == "Sampler"),
            "cbuffer_parameters": sum(1 for item in shader.parameters.items if item.type == "CBuffer"),
            "buffer_sizes": shader.parameters.buffer_sizes,
        }
        if shader.parameters.items:
            self.warnings.append(
                f"ShaderFX {shader.name!r} parameter XML was serialized to a structured side table; native ShaderFX binding offsets still need sample-based confirmation"
            )
        return self.record(name, "ShaderParameterTable", self.system, offset, len(payload), metadata)

    def write_shader_fx(self, name: str, shader: ShaderXml, parameter_table: BinaryObjectRecord) -> BinaryObjectRecord:
        offset = self.system.allocate(self.SHADER_FX_SIZE, 16)
        shader_hash = joaat(shader.name)
        self.system.pack_into(
            f"{self.struct_endian}QII BBHH II I HBB Q",
            offset,
            shader_hash,
            shader.draw_bucket,
            len(shader.parameters.items),
            1 if shader.draw_bucket_flag else 0,
            0,
            32768,
            0,
            len([item for item in shader.parameters.items if item.type == "Texture"]),
            len([item for item in shader.parameters.items if item.type == "Sampler"]),
            0xFF01,
            len([item for item in shader.parameters.items if item.type == "CBuffer"]),
            0,
            0,
            parameter_table.pointer,
        )
        metadata = {
            "shader": shader.name,
            "shader_hash": f"0x{shader_hash:08X}",
            "draw_bucket": shader.draw_bucket,
            "parameter_table": parameter_table.pointer_hex,
            "parameter_count": len(shader.parameters.items),
        }
        item = self.record(name, "ShaderFX", self.system, offset, self.SHADER_FX_SIZE, metadata)
        self.fixup(item.name, "ParameterTablePointer", offset + 0x26, parameter_table)
        return item

    def texture_source_candidates(self, drawable: DrawableXml, texture: TextureXml) -> list[Path]:
        if drawable.source_xml_path is None:
            return []
        base = drawable.source_xml_path.parent
        return [
            base / drawable.name / f"{texture.name}.png",
            base / f"{texture.name}.png",
            base / drawable.name / f"{texture.name}.dds",
            base / f"{texture.name}.dds",
        ]

    def write_texture_payload(self, name: str, drawable: DrawableXml, texture: TextureXml) -> BinaryObjectRecord:
        source = next((candidate for candidate in self.texture_source_candidates(drawable, texture) if candidate.exists()), None)
        if source is None:
            payload = b""
            metadata = {"texture": texture.name, "flags": texture.flags, "source": None, "status": "missing"}
            self.warnings.append(f"Texture {texture.name!r} has no source image beside the XML export")
        else:
            payload = source.read_bytes()
            dimensions = png_dimensions(payload)
            metadata = {
                "texture": texture.name,
                "flags": texture.flags,
                "source": str(source),
                "source_format": source.suffix.lower().lstrip("."),
                "source_size": len(payload),
                "width": dimensions[0] if dimensions else None,
                "height": dimensions[1] if dimensions else None,
                "status": "source_payload_serialized",
            }
            self.warnings.append(
                f"Texture {texture.name!r} source payload serialized from {source.name}; native RDR2 texture mip/surface encoding is not implemented yet"
            )
        offset = self.graphics.allocate(len(payload), 16)
        self.graphics.write(offset, payload)
        return self.record(name, "TexturePayload", self.graphics, offset, len(payload), metadata)

    def write_texture_dictionary(self, drawable: DrawableXml, texture_payloads: list[BinaryObjectRecord]) -> BinaryObjectRecord:
        offset = self.system.allocate(self.TEXTURE_DICTIONARY_SIZE, 16)
        pointer_array_offset = self.system.allocate(max(1, len(texture_payloads)) * 8, 16)
        for index, payload in enumerate(texture_payloads):
            self.system.pack_into(f"{self.struct_endian}Q", pointer_array_offset + index * 8, payload.pointer)
        pointer_array = self.record(
            "TexturePointerArray",
            "PointerArray",
            self.system,
            pointer_array_offset,
            max(1, len(texture_payloads)) * 8,
            {"texture_count": len(texture_payloads)},
        )
        self.system.pack_into(
            f"{self.struct_endian}IIQIIII",
            offset,
            joaat("TextureDictionary"),
            1,
            pointer_array.pointer,
            len(texture_payloads),
            len(texture_payloads),
            len(drawable.shader_group.textures),
            0,
        )
        metadata = {
            "texture_count": len(drawable.shader_group.textures),
            "payload_count": len(texture_payloads),
            "texture_names": drawable.shader_group.texture_names,
            "texture_pointer_array": pointer_array.pointer_hex,
        }
        item = self.record("TextureDictionary", "TextureDictionary", self.system, offset, self.TEXTURE_DICTIONARY_SIZE, metadata)
        self.fixup(item.name, "TexturePointerArray", offset + 0x08, pointer_array)
        for index, payload in enumerate(texture_payloads):
            self.fixup(pointer_array.name, payload.name, pointer_array_offset + index * 8, payload)
        return item

    def write_shader_group(self, drawable: DrawableXml, texture_dictionary: BinaryObjectRecord, shader_records: list[BinaryObjectRecord]) -> BinaryObjectRecord:
        pointer_array_offset = self.system.allocate(len(shader_records) * 8, 16)
        for index, shader in enumerate(shader_records):
            self.system.pack_into("<Q", pointer_array_offset + index * 8, shader.pointer)
        pointer_array = self.record("ShaderPointerArray", "PointerArray", self.system, pointer_array_offset, len(shader_records) * 8)
        offset = self.system.allocate(self.SHADER_GROUP_SIZE, 16)
        self.system.pack_into(
            "<IIQQHHIQQIIQ",
            offset,
            1080113136,
            1,
            texture_dictionary.pointer,
            pointer_array.pointer,
            len(shader_records),
            len(shader_records),
            0,
            0,
            0,
            self.SHADER_GROUP_SIZE // 16,
            0,
            0,
        )
        item = self.record("ShaderGroup", "ShaderGroup", self.system, offset, self.SHADER_GROUP_SIZE)
        self.fixup(item.name, "TextureDictionaryPointer", offset + 0x08, texture_dictionary)
        self.fixup(item.name, "ShadersPointer", offset + 0x10, pointer_array)
        return item

    def write_drawable(self, drawable: DrawableXml, shader_group: BinaryObjectRecord, model_records: list[BinaryObjectRecord]) -> None:
        offset = 0
        self.system.data[: self.DRAWABLE_BASE_SIZE] = b"\x00" * self.DRAWABLE_BASE_SIZE
        model_list_offset = self.system.allocate(16 + len(model_records) * 8, 16)
        model_array_offset = model_list_offset + 16
        for index, model in enumerate(model_records):
            self.system.pack_into("<Q", model_array_offset + index * 8, model.pointer)
        model_list_pointer = self.system.pointer(model_list_offset)
        model_array_pointer = self.system.pointer(model_array_offset)
        self.system.pack_into("<QHHI", model_list_offset, model_array_pointer, len(model_records), len(model_records), 0)

        self.system.pack_into("<IIQ", offset, 1079456120, 1, 0)
        self.system.pack_into("<Q", offset + 0x10, shader_group.pointer)
        self.system.pack_into("<Q", offset + 0x50, model_list_pointer)
        self.system.pack_into("<ffff", offset + 0x70, 9998.0, 9998.0, 9998.0, 9998.0)
        self.system.pack_into("<IIII", offset + 0x80, 1, 0, 0, 0)
        self.system.pack_into("<HHIQ", offset + 0x98, 0, align(16 + len(model_records) * 8, 16) // 16, 0, model_list_pointer)
        root = self.record("Drawable", "Drawable", self.system, offset, self.DRAWABLE_BASE_SIZE)
        model_list = self.record("DrawableModelsHigh", "DrawableModelList", self.system, model_list_offset, 16 + len(model_records) * 8)
        self.fixup(root.name, "ShaderGroupPointer", offset + 0x10, shader_group)
        self.fixup(root.name, "DrawableModelsHighPointer", offset + 0x50, model_list)
        self.fixup(root.name, "DrawableModelsPointer", offset + 0xA0, model_list)

    def build(self, drawable: DrawableXml, resource_format: str = "rsc7") -> tuple[bytes, BinaryWriteReport]:
        self.system.allocate(self.DRAWABLE_BASE_SIZE, 16)
        geometry_records_by_model: list[list[BinaryObjectRecord]] = []
        for model_index, model in enumerate(drawable.models):
            geometry_records: list[BinaryObjectRecord] = []
            for geometry_index, geometry in enumerate(model.geometries):
                vertex_data, stride = self.write_vertex_data(f"VertexData[{model_index}:{geometry_index}]", geometry)
                index_data, index_packing = self.write_index_data(f"IndexData[{model_index}:{geometry_index}]", geometry)
                vertex_buffer = self.write_vertex_buffer(f"VertexBuffer[{model_index}:{geometry_index}]", geometry, vertex_data, stride)
                index_buffer = self.write_index_buffer(
                    f"IndexBuffer[{model_index}:{geometry_index}]",
                    geometry,
                    index_data,
                    index_packing,
                )
                geometry_records.append(
                    self.write_geometry(
                        f"DrawableGeometry[{model_index}:{geometry_index}]",
                        geometry,
                        vertex_buffer,
                        index_buffer,
                        vertex_data,
                        stride,
                    )
                )
            geometry_records_by_model.append(geometry_records)
        model_records = [
            self.write_model(f"DrawableModel[{index}]", model, geometry_records_by_model[index])
            for index, model in enumerate(drawable.models)
        ]
        texture_payloads = [
            self.write_texture_payload(f"TexturePayload[{index}]", drawable, texture)
            for index, texture in enumerate(drawable.shader_group.textures)
        ]
        texture_dictionary = self.write_texture_dictionary(drawable, texture_payloads)
        shader_records = []
        for index, shader in enumerate(drawable.shader_group.shaders):
            parameter_table = self.write_shader_parameter_table(f"ShaderParameterTable[{index}]", shader)
            shader_records.append(self.write_shader_fx(f"ShaderFX[{index}]", shader, parameter_table))
        shader_group = self.write_shader_group(drawable, texture_dictionary, shader_records)
        self.write_drawable(drawable, shader_group, model_records)

        system_data = self.system.aligned_bytes(0x2000)
        graphics_data = self.graphics.aligned_bytes(0x2000) if self.graphics.data else b""
        system_flags = encode_page_flags(len(system_data), version=(self.version >> 4) & 0xF)
        graphics_flags = (
            encode_page_flags(len(graphics_data), version=self.version & 0xF)
            if graphics_data
            else (self.version & 0xF) << 28
        )
        if resource_format == "rsc7":
            data = RSC7_MAGIC + struct.pack("<III", self.version, system_flags, graphics_flags) + system_data + graphics_data
        elif resource_format == "rsc8":
            data = RSC8_MAGIC + struct.pack("<III", self.version, system_flags, graphics_flags) + system_data + graphics_data
            self.warnings.append(
                "RSC8 output uses experimental RSC7-compatible page words; native RDR2 RSC8 page-word semantics are not fully confirmed"
            )
        else:
            raise ParseError(f"unsupported resource format: {resource_format}")
        report = BinaryWriteReport(
            output_path="",
            version=self.version,
            system_size=len(system_data),
            graphics_size=len(graphics_data),
            objects=self.objects,
            fixups=self.fixups,
            warnings=self.warnings,
        )
        return data, report


@dataclass
class ParseContext:
    trace_enabled: bool = False
    debug: bool = False
    hex_window_size: int = 64
    trace: list[ParseTraceEvent] = field(default_factory=list)
    hex_windows: list[HexWindow] = field(default_factory=list)

    def add_trace(self, label: str, message: str, offset: int | None = None, length: int | None = None) -> None:
        if self.trace_enabled or self.debug:
            self.trace.append(ParseTraceEvent(label=label, message=message, offset=offset, length=length))

    def add_hex_window(self, view: "BinaryView", offset: int, label: str, size: int | None = None) -> None:
        if not self.debug:
            return
        window_size = self.hex_window_size if size is None else size
        if window_size <= 0 or view.size == 0:
            return
        start = max(0, offset - (window_size // 2))
        end = min(view.size, start + window_size)
        chunk = view.data[start:end]
        self.hex_windows.append(
            HexWindow(
                label=label,
                offset=start,
                length=len(chunk),
                hex=" ".join(f"{byte:02X}" for byte in chunk),
                ascii="".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk),
            )
        )


class BinaryView:
    def __init__(self, data: bytes) -> None:
        self.data = data

    @property
    def size(self) -> int:
        return len(self.data)

    def require(self, offset: int, length: int, label: str) -> None:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ParseError(
                f"{label} is out of bounds: offset={offset}, length={length}, file_size={self.size}"
            )

    def u16(self, offset: int) -> int:
        self.require(offset, 2, "u16")
        return struct.unpack_from("<H", self.data, offset)[0]

    def u24(self, offset: int) -> int:
        self.require(offset, 3, "u24")
        b0, b1, b2 = self.data[offset : offset + 3]
        return b0 | (b1 << 8) | (b2 << 16)

    def u32(self, offset: int) -> int:
        self.require(offset, 4, "u32")
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64(self, offset: int) -> int:
        self.require(offset, 8, "u64")
        return struct.unpack_from("<Q", self.data, offset)[0]

    def bytes(self, offset: int, length: int) -> bytes:
        self.require(offset, length, "bytes")
        return self.data[offset : offset + length]


def decode_page_flags(flags: int) -> PageFlags:
    """Decode RAGE resource page flags using the CodeWalker-compatible layout."""

    s0 = ((flags >> 27) & 0x1) << 0
    s1 = ((flags >> 26) & 0x1) << 1
    s2 = ((flags >> 25) & 0x1) << 2
    s3 = ((flags >> 24) & 0x1) << 3
    s4 = ((flags >> 17) & 0x7F) << 4
    s5 = ((flags >> 11) & 0x3F) << 5
    s6 = ((flags >> 7) & 0xF) << 6
    s7 = ((flags >> 5) & 0x3) << 7
    s8 = ((flags >> 4) & 0x1) << 8
    base_shift = flags & 0xF
    base_size = 0x200 << base_shift
    page_units = s0 + s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8
    return PageFlags(
        raw_hex=f"0x{flags:08X}",
        version_nibble=(flags >> 28) & 0xF,
        base_shift=base_shift,
        base_size=base_size,
        page_units=page_units,
        decoded_size=base_size * page_units,
    )


def encode_page_flags(size: int, version: int = 0) -> int:
    """Encode a page size into the same page flag layout we decode."""

    if size <= 0 or size % 0x200 != 0:
        raise ParseError(f"resource section size must be a positive multiple of 0x200: {size}")
    fields = (
        ("s8", 256, 0x1, 4),
        ("s7", 128, 0x3, 5),
        ("s6", 64, 0xF, 7),
        ("s5", 32, 0x3F, 11),
        ("s4", 16, 0x7F, 17),
        ("s3", 8, 0x1, 24),
        ("s2", 4, 0x1, 25),
        ("s1", 2, 0x1, 26),
        ("s0", 1, 0x1, 27),
    )
    for shift in range(16):
        base_size = 0x200 << shift
        if size % base_size != 0:
            continue
        remaining = size // base_size
        encoded: dict[str, int] = {}
        for name, weight, maximum, _ in fields:
            value = min(maximum, remaining // weight)
            encoded[name] = value
            remaining -= value * weight
        if remaining == 0:
            flags = ((version & 0xF) << 28) | (shift & 0xF)
            for name, _, maximum, bit_offset in fields:
                flags |= (encoded[name] & maximum) << bit_offset
            return flags
    raise ParseError(f"resource section size is too large for page flag encoding: {size}")


def parse_rsc7(view: BinaryView, ctx: ParseContext | None = None) -> Rsc7Header:
    if ctx:
        ctx.add_trace("rsc7.header", "reading RSC7 header", offset=0, length=16)
        ctx.add_hex_window(view, 0, "RSC7 header")
    view.require(0, 16, "RSC7 header")
    magic = view.bytes(0, 4)
    if magic != RSC7_MAGIC:
        raise ParseError("missing RSC7 magic")
    system_flags = decode_page_flags(view.u32(8))
    graphics_flags = decode_page_flags(view.u32(12))
    payload_size = max(0, view.size - 16)
    if ctx:
        ctx.add_trace(
            "rsc7.header",
            (
                f"magic=0x{int.from_bytes(magic, 'little'):08X}, version={view.u32(4)}, "
                f"system_size={system_flags.decoded_size}, graphics_size={graphics_flags.decoded_size}"
            ),
            offset=0,
            length=16,
        )
    return Rsc7Header(
        magic=magic.decode("ascii"),
        version=view.u32(4),
        system_flags=system_flags,
        graphics_flags=graphics_flags,
        payload_size=payload_size,
        decoded_total_size=system_flags.decoded_size + graphics_flags.decoded_size,
    )


def looks_like_legacy_rsc_page_words(word1: int, word2: int, word3: int, file_size: int) -> bool:
    if not (0 < word1 <= 255):
        return False
    system_flags = decode_page_flags(word2)
    graphics_flags = decode_page_flags(word3)
    decoded_total = system_flags.decoded_size + graphics_flags.decoded_size
    return decoded_total > 0 and decoded_total <= max(0, file_size - 16)


def parse_rsc8(view: BinaryView, ctx: ParseContext | None = None) -> Rsc8Header:
    if ctx:
        ctx.add_trace("rsc8.header", "reading RSC8 header", offset=0, length=16)
        ctx.add_hex_window(view, 0, "RSC8 header")
    view.require(0, 16, "RSC8 header")
    magic = view.bytes(0, 4)
    if magic != RSC8_MAGIC:
        raise ParseError("missing RSC8 magic")
    word1 = view.u32(4)
    word2 = view.u32(8)
    word3 = view.u32(12)
    header = Rsc8Header(
        magic=magic.decode("ascii"),
        word1=word1,
        word2=word2,
        word3=word3,
        payload_size=max(0, view.size - 16),
    )
    if looks_like_legacy_rsc_page_words(word1, word2, word3, view.size):
        header.legacy_version = word1
        header.system_flags = decode_page_flags(word2)
        header.graphics_flags = decode_page_flags(word3)
        header.interpretation = "experimental-rsc8-with-rsc7-page-words"
    if ctx:
        ctx.add_trace(
            "rsc8.header",
            (
                f"word1={header.word1_hex}, word2={header.word2_hex}, "
                f"word3={header.word3_hex}, interpretation={header.interpretation}"
            ),
            offset=0,
            length=16,
        )
    return header


def parse_xml_model_counts(xml_path: Path) -> ModelCounts:
    tree = ElementTree.parse(xml_path)
    root = tree.getroot()
    if root.tag not in {"RDR2Drawable", "Drawable"}:
        raise ParseError(f"unsupported drawable XML root: {root.tag}")

    lod_map = {
        "high": "LodHigh",
        "medium": "LodMed",
        "low": "LodLow",
        "very_low": "LodVlow",
    }
    values: dict[str, int] = {}
    for key, tag in lod_map.items():
        models = root.find(f"./{tag}/Models")
        values[key] = 0 if models is None else len(models.findall("./Item"))
    return ModelCounts(
        high=values["high"],
        medium=values["medium"],
        low=values["low"],
        very_low=values["very_low"],
    )


def child_text(element: ElementTree.Element, path: str, default: str = "") -> str:
    child = element.find(path)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def child_int_value(element: ElementTree.Element, path: str, default: int = 0) -> int:
    child = element.find(path)
    if child is None:
        return default
    value = child.attrib.get("value")
    if value is None:
        return default
    return int(value)


def child_bool_value(element: ElementTree.Element, path: str, default: bool = False) -> bool:
    child = element.find(path)
    if child is None:
        return default
    value = child.attrib.get("value")
    if value is None:
        return default
    return value.strip().lower() == "true"


def count_vertex_rows(text: str | None) -> int:
    if not text:
        return 0
    return sum(1 for line in text.splitlines() if line.strip())


def parse_indices(text: str | None) -> list[int]:
    if not text:
        return []
    return [int(value) for value in text.split()]


def parse_vertex_rows(text: str | None) -> list[VertexRowXml]:
    if not text:
        return []
    rows: list[VertexRowXml] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parts = [part.strip() for part in stripped.split("\t") if part.strip()]
        if len(parts) != 5:
            raise ParseError(f"vertex row {line_number} expected 5 tab-separated fields, got {len(parts)}")
        position = tuple(float(value) for value in parts[0].split())
        normal = tuple(float(value) for value in parts[1].split())
        tangent = tuple(float(value) for value in parts[2].split())
        color = tuple(int(value) for value in parts[3].split())
        uv = tuple(float(value) for value in parts[4].split())
        if len(position) != 3 or len(normal) != 4 or len(tangent) != 4 or len(color) != 4 or len(uv) != 2:
            raise ParseError(f"vertex row {line_number} has invalid PNXCT component counts")
        rows.append(
            VertexRowXml(
                position=position,  # type: ignore[arg-type]
                normal=normal,  # type: ignore[arg-type]
                tangent=tangent,  # type: ignore[arg-type]
                color=color,  # type: ignore[arg-type]
                uv=uv,  # type: ignore[arg-type]
            )
        )
    return rows


def parse_int_list(text: str | None) -> list[int]:
    if not text:
        return []
    return [int(value) for value in text.split()]


def attr_int(element: ElementTree.Element, name: str, default: int | None = None) -> int | None:
    value = element.get(name)
    return default if value is None else int(value)


def attr_float(element: ElementTree.Element, name: str) -> float | None:
    value = element.get(name)
    return None if value is None else float(value)


def parse_shader_parameter_xml(element: ElementTree.Element) -> ShaderParameterXml:
    values = tuple(
        value
        for value in (
            attr_float(element, "x"),
            attr_float(element, "y"),
            attr_float(element, "z"),
            attr_float(element, "w"),
        )
        if value is not None
    )
    return ShaderParameterXml(
        name=element.get("name", ""),
        type=element.get("type", ""),
        index=attr_int(element, "index"),
        texture=element.get("texture"),
        sampler=attr_int(element, "sampler"),
        flags=attr_int(element, "flags"),
        buffer=attr_int(element, "buffer"),
        offset=attr_int(element, "offset"),
        length=attr_int(element, "length"),
        values=values,
    )


def parse_shader_parameters_xml(element: ElementTree.Element) -> ShaderParametersXml:
    parameters = element.find("./Parameters")
    if parameters is None:
        return ShaderParametersXml()
    return ShaderParametersXml(
        buffer_sizes=parse_int_list(child_text(parameters, "./BufferSizes")),
        items=[
            parse_shader_parameter_xml(item)
            for item in parameters.findall("./Items/Item")
        ],
    )


def parse_shader_group_xml(root: ElementTree.Element) -> ShaderGroupXml:
    shader_group = root.find("./ShaderGroup")
    if shader_group is None:
        return ShaderGroupXml(shaders=[], textures=[])
    textures = [
        TextureXml(
            name=child_text(item, "./Name"),
            flags=child_int_value(item, "./Flags", 0),
        )
        for item in shader_group.findall("./TextureDictionary/Textures/Item")
        if child_text(item, "./Name")
    ]
    shaders = [
        ShaderXml(
            name=child_text(item, "./Name"),
            draw_bucket=child_int_value(item, "./DrawBucket", 0),
            draw_bucket_flag=child_bool_value(item, "./DrawBucketFlag", False),
            parameters=parse_shader_parameters_xml(item),
        )
        for item in shader_group.findall("./Shaders/Item")
        if child_text(item, "./Name")
    ]
    return ShaderGroupXml(shaders=shaders, textures=textures)


def parse_geometry_xml(element: ElementTree.Element, shaders: list[str]) -> DrawableGeometryXml:
    shader_id = child_int_value(element, "./ShaderID", 0)
    shader_name = shaders[shader_id] if 0 <= shader_id < len(shaders) else None
    vertex_layout = element.find("./VertexLayout")
    if vertex_layout is None:
        raise ParseError("geometry is missing VertexLayout")
    semantics = child_text(vertex_layout, "./Semantics")
    formats = parse_int_list(child_text(vertex_layout, "./Formats"))
    non_interleaved = child_bool_value(vertex_layout, "./NonInterleaved", False)
    vertices = element.find("./Vertices")
    vertex_rows = parse_vertex_rows(vertices.text if vertices is not None else None)
    indices = parse_indices(child_text(element, "./Indices"))
    index_count = len(indices)
    return DrawableGeometryXml(
        shader_id=shader_id,
        shader_name=shader_name,
        vertex_buffer=VertexBufferXml(
            layout_semantics=semantics,
            formats=formats,
            non_interleaved=non_interleaved,
            vertex_count=len(vertex_rows),
            vertices=vertex_rows,
        ),
        index_buffer=IndexBufferXml(
            index_count=index_count,
            triangle_count=index_count // 3,
            max_index=max(indices) if indices else None,
            indices=indices,
        ),
    )


def parse_model_xml(element: ElementTree.Element, lod: str, shaders: list[str]) -> DrawableModelXml:
    geometries = [
        parse_geometry_xml(geometry, shaders)
        for geometry in element.findall("./Geometries/Item")
    ]
    return DrawableModelXml(
        lod=lod,
        flags=child_int_value(element, "./Flags", 0),
        has_skin=child_bool_value(element, "./HasSkin", False),
        bone_index=child_int_value(element, "./BoneIndex", 0),
        bones_count=child_int_value(element, "./BonesCount", 0),
        geometries=geometries,
    )


def parse_drawable_xml(xml_path: Path) -> DrawableXml:
    tree = ElementTree.parse(xml_path)
    root = tree.getroot()
    if root.tag not in {"RDR2Drawable", "Drawable"}:
        raise ParseError(f"unsupported drawable XML root: {root.tag}")

    shader_group = parse_shader_group_xml(root)
    lod_paths = (
        ("high", "./LodHigh/Models/Item"),
        ("medium", "./LodMed/Models/Item"),
        ("low", "./LodLow/Models/Item"),
        ("very_low", "./LodVlow/Models/Item"),
    )
    models: list[DrawableModelXml] = []
    shader_names = shader_group.shader_names
    for lod, path in lod_paths:
        models.extend(parse_model_xml(model, lod, shader_names) for model in root.findall(path))
    return DrawableXml(
        name=child_text(root, "./Name"),
        hash_name=child_text(root, "./Hash"),
        shader_group=shader_group,
        models=models,
        source_xml_path=xml_path,
    )


def print_drawable_xml_summary(drawable: DrawableXml) -> None:
    print(f"Name: {drawable.name}")
    print(f"Models: {drawable.model_count}")
    print(f"Geometries: {drawable.geometry_count}")
    print(f"Vertices: {drawable.vertex_count}")
    print(f"Indices: {drawable.index_count}")
    print(f"Shader: {drawable.primary_shader or '<none>'}")
    print(f"Texture: {drawable.primary_texture or '<none>'}")
    print(f"Vertex Layout: {drawable.primary_vertex_layout or '<none>'}")


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_metadata_ydr(
    model_counts: ModelCounts | dict[str, int],
    version: int = 165,
    system_size: int = 8192,
    graphics_size: int = 0,
) -> bytes:
    """Build a minimal inspectable RSC7/YDR resource.

    This is intentionally not a game-ready drawable. It creates a valid top-level
    RSC7 wrapper and DrawableBase model-list headers so pointer mapping,
    boundaries, alignment, and counts can be verified from CLI output.
    """

    payload = bytearray(system_size + graphics_size)
    if len(payload) < 0x200:
        raise ParseError("system section is too small for a drawable fixture")
    if isinstance(model_counts, dict):
        model_counts = ModelCounts(
            high=model_counts.get("high", 0),
            medium=model_counts.get("medium", 0),
            low=model_counts.get("low", 0),
            very_low=model_counts.get("very_low", 0),
        )

    # ResourceFileBase: FileVFT, FileUnknown, FilePagesInfoPointer.
    struct.pack_into("<IIQ", payload, 0, 1079456120, 1, 0)

    lod_pointer_offsets = {
        "high": 0x50,
        "medium": 0x58,
        "low": 0x60,
        "very_low": 0x68,
    }
    cursor = 0x100
    model_pointer_cursor = 0x400
    for lod_name, drawable_offset in lod_pointer_offsets.items():
        count = getattr(model_counts, lod_name)
        if count <= 0:
            struct.pack_into("<Q", payload, drawable_offset, 0)
            continue
        cursor = align(cursor, 16)
        pointer_array_offset = cursor + 16
        pointer_array_size = count * 8
        end = pointer_array_offset + pointer_array_size
        if end > len(payload):
            raise ParseError(f"not enough system space for {lod_name} model pointer list")
        list_pointer = 0x50000000 + cursor
        array_pointer = 0x50000000 + pointer_array_offset
        struct.pack_into("<Q", payload, drawable_offset, list_pointer)
        struct.pack_into("<QHHI", payload, cursor, array_pointer, count, count, 0)
        for index in range(count):
            struct.pack_into("<Q", payload, pointer_array_offset + index * 8, 0x50000000 + model_pointer_cursor)
            model_pointer_cursor += 0xA8
        cursor = end

    system_flags = encode_page_flags(system_size, version=(version >> 4) & 0xF)
    graphics_flags = encode_page_flags(graphics_size, version=version & 0xF) if graphics_size else (version & 0xF) << 28
    return RSC7_MAGIC + struct.pack("<III", version, system_flags, graphics_flags) + bytes(payload)


def write_sample_fixture(path: Path = DEFAULT_FIXTURE_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = build_metadata_ydr(ModelCounts(high=3))
    path.write_bytes(data)
    return path


def pack_ydr_xml(xml_path: Path, output_path: Path, version: int = 165) -> tuple[Path, ModelCounts]:
    counts = parse_xml_model_counts(xml_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(build_metadata_ydr(counts, version=version))
    return output_path, counts


def write_ydr_xml_structures(
    xml_path: Path,
    output_path: Path,
    version: int = 165,
    endian: str = "little",
    resource_format: str = "rsc7",
) -> BinaryWriteReport:
    drawable = parse_drawable_xml(xml_path)
    writer = RageBinaryStructureWriter(version=version, endian=endian)
    data, report = writer.build(drawable, resource_format=resource_format)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)
    report.output_path = str(output_path.resolve())
    return report


def print_binary_write_report(report: BinaryWriteReport) -> None:
    print(f"Wrote structured YDR: {report.output_path}")
    print(f"Version: {report.version}")
    print(f"System size: {report.system_size}")
    print(f"Graphics size: {report.graphics_size}")
    print(f"Objects: {len(report.objects)}")
    print(f"Fixups: {len(report.fixups)}")
    if report.objects:
        print("\nBinary objects")
        for item in report.objects:
            metadata = format_object_metadata(item.metadata)
            print(
                f"  {item.name}: type={item.type}, section={item.section}, "
                f"offset=0x{item.offset:X}, pointer={item.pointer_hex}, size={item.size}{metadata}"
            )
    if report.warnings:
        print("\nWriter warnings")
        for warning in report.warnings:
            print(f"  [warning] {warning}")


def format_object_metadata(metadata: dict[str, Any]) -> str:
    if not metadata:
        return ""
    keys = (
        "vertex_layout",
        "stride",
        "vertex_count",
        "index_size_bits",
        "index_count",
        "triangle_count",
        "max_index",
        "alignment",
        "endian",
        "data_size",
        "texture_count",
        "payload_count",
        "source_format",
        "width",
        "height",
        "shader",
        "shader_hash",
        "parameter_count",
        "texture_parameters",
        "sampler_parameters",
        "cbuffer_parameters",
    )
    parts = [f"{key}={metadata[key]}" for key in keys if key in metadata]
    return f", metadata=({', '.join(parts)})" if parts else ""


def try_decompress_deflate(data: bytes) -> bytes | None:
    for window_bits in (-zlib.MAX_WBITS, zlib.MAX_WBITS):
        try:
            return zlib.decompress(data, window_bits)
        except zlib.error:
            continue
    return None


def get_resource_payload(data: bytes, header: Rsc7Header | Rsc8Header) -> tuple[bytes, str]:
    payload = data[header.payload_offset :]
    expected_size = header.decoded_total_size
    if expected_size is None:
        raise ParseError("resource header does not expose decoded system/graphics page sizes")
    if expected_size == 0:
        return payload, "raw"
    if len(payload) >= expected_size:
        return payload, "raw"
    inflated = try_decompress_deflate(payload)
    if inflated is None:
        raise ParseError(
            "resource payload is smaller than declared resource size and did not inflate as deflate"
        )
    if len(inflated) < expected_size:
        raise ParseError(
            f"inflated payload is smaller than declared resource size: "
            f"inflated={len(inflated)}, declared={expected_size}"
        )
    return inflated, "deflate"


def build_resource_layout(system_size: int, graphics_size: int) -> ResourceLayout:
    return ResourceLayout(
        system=ResourceSection(
            name="system",
            virtual_base=0x50000000,
            payload_offset=0,
            size=system_size,
        ),
        graphics=ResourceSection(
            name="graphics",
            virtual_base=0x60000000,
            payload_offset=system_size,
            size=graphics_size,
        ),
    )


def read_resource_pointer_list(
    payload_view: BinaryView,
    pointer: int,
    layout: ResourceLayout,
    label: str,
    lod: str,
    owner_field_offset: int,
    ctx: ParseContext | None = None,
    max_count: int = 4096,
) -> DrawableModelListInfo:
    address = layout.resolve(pointer)
    if address is None:
        raise ParseError(f"{label} pointer 0x{pointer:016X} is outside resource sections")
    offset = address.payload_offset
    if ctx:
        ctx.add_trace(label, f"resolved list pointer 0x{pointer:016X} to {address.section}+0x{offset:X}", offset, 16)
        ctx.add_hex_window(payload_view, offset, f"{label} list header")
    payload_view.require(offset, 16, f"{label} pointer-list header")
    pointer_array = payload_view.u64(offset)
    count = payload_view.u16(offset + 8)
    capacity = payload_view.u16(offset + 10)
    if count > capacity:
        raise ParseError(f"{label} count {count} exceeds capacity {capacity}")
    if capacity > max_count:
        raise ParseError(f"{label} capacity {capacity} exceeds safety limit {max_count}")
    pointer_array_address = layout.resolve(pointer_array)
    if count and pointer_array_address is None:
        raise ParseError(f"{label} pointer array 0x{pointer_array:016X} is outside resource sections")
    pointer_array_offset = None if pointer_array_address is None else pointer_array_address.payload_offset
    if count and pointer_array_offset is not None:
        if ctx:
            ctx.add_trace(
                label,
                f"validated pointer array 0x{pointer_array:016X} count={count} capacity={capacity}",
                pointer_array_offset,
                count * 8,
            )
            ctx.add_hex_window(payload_view, pointer_array_offset, f"{label} pointer array")
        payload_view.require(pointer_array_offset, count * 8, f"{label} pointer array")
    model_pointers = []
    if count and pointer_array_offset is not None:
        model_pointers = [payload_view.u64(pointer_array_offset + index * 8) for index in range(count)]
    return DrawableModelListInfo(
        lod=lod,
        owner_field_offset=owner_field_offset,
        pointer=pointer,
        payload_offset=offset,
        pointer_array=pointer_array,
        pointer_array_payload_offset=pointer_array_offset,
        count=count,
        capacity=capacity,
        model_pointers=model_pointers,
    )


def validate_resource_pointer(
    payload_view: BinaryView,
    layout: ResourceLayout,
    pointer: int,
    label: str,
    required_length: int = 0,
) -> BoundaryValidation:
    if pointer == 0:
        return BoundaryValidation(
            pointer="0x0000000000000000",
            label=label,
            status="null",
            required_length=required_length or None,
            message="pointer is null",
        )
    address = layout.resolve(pointer)
    if address is None:
        return BoundaryValidation(
            pointer=f"0x{pointer:016X}",
            label=label,
            status="invalid",
            required_length=required_length or None,
            message="pointer is outside system/graphics resource boundaries",
        )
    if required_length:
        try:
            payload_view.require(address.payload_offset, required_length, label)
        except ParseError as exc:
            return BoundaryValidation(
                pointer=f"0x{pointer:016X}",
                label=label,
                status="invalid",
                section=address.section,
                payload_offset=address.payload_offset,
                required_length=required_length,
                message=str(exc),
            )
    return BoundaryValidation(
        pointer=f"0x{pointer:016X}",
        label=label,
        status="valid",
        section=address.section,
        payload_offset=address.payload_offset,
        required_length=required_length or None,
        message="within resource boundaries",
    )


def add_graph_pointer(
    resource_map: ResourceMap,
    payload_view: BinaryView,
    layout: ResourceLayout,
    source_id: str,
    field: str,
    pointer: int,
    target_type: str,
    target_label: str,
    required_length: int = 0,
) -> ResourceMapNode | None:
    validation = validate_resource_pointer(payload_view, layout, pointer, target_label, required_length)
    resource_map.boundary_validations.append(validation)
    target_id = f"{target_type}:{validation.pointer}"
    resource_map.edges.append(
        ResourceMapEdge(
            source=source_id,
            target=target_id,
            field=field,
            pointer=validation.pointer,
            status=validation.status,
        )
    )
    if validation.status != "valid":
        return None
    if any(node.id == target_id for node in resource_map.nodes):
        return next(node for node in resource_map.nodes if node.id == target_id)
    node = ResourceMapNode(
        id=target_id,
        label=target_label,
        type=target_type,
        pointer=validation.pointer,
        section=validation.section,
        payload_offset=validation.payload_offset,
        length=required_length or None,
    )
    resource_map.nodes.append(node)
    return node


def read_pointer_array(payload_view: BinaryView, offset: int, count: int) -> list[int]:
    return [payload_view.u64(offset + index * 8) for index in range(count)]


def build_ydr_resource_map(
    payload_view: BinaryView,
    layout: ResourceLayout,
    model_lists: list[DrawableModelListInfo],
    ctx: ParseContext | None = None,
) -> ResourceMap:
    drawable_pointer = 0x50000000
    drawable_node = ResourceMapNode(
        id=f"Drawable:0x{drawable_pointer:016X}",
        label="Drawable",
        type="Drawable",
        pointer=f"0x{drawable_pointer:016X}",
        section="system",
        payload_offset=0,
        length=168,
    )
    resource_map = ResourceMap(root=drawable_node.id, nodes=[drawable_node])
    drawable_validation = validate_resource_pointer(payload_view, layout, drawable_pointer, "Drawable", 168)
    resource_map.boundary_validations.append(drawable_validation)

    direct_fields = [
        ("ShaderGroup", 0x10, "ShaderGroup", "ShaderGroup", 64),
        ("Skeleton", 0x18, "Skeleton", "Skeleton", 16),
        ("Joints", 0x90, "Joints", "Joints", 16),
        ("DrawableModelsPointer", 0xA0, "DrawableModelsBlock", "DrawableModels", 16),
    ]
    for field, offset, target_type, label, length in direct_fields:
        pointer = payload_view.u64(offset)
        if ctx:
            ctx.add_trace("resource_map.drawable", f"{field}=0x{pointer:016X}", offset, 8)
        add_graph_pointer(resource_map, payload_view, layout, drawable_node.id, field, pointer, target_type, label, length)

    shader_group_node = next((node for node in resource_map.nodes if node.type == "ShaderGroup"), None)
    if shader_group_node is not None and shader_group_node.payload_offset is not None:
        shader_group_offset = shader_group_node.payload_offset
        texture_dictionary_pointer = payload_view.u64(shader_group_offset + 0x08)
        shader_pointer_array = payload_view.u64(shader_group_offset + 0x10)
        shader_count = payload_view.u16(shader_group_offset + 0x18)
        add_graph_pointer(
            resource_map,
            payload_view,
            layout,
            shader_group_node.id,
            "TextureDictionary",
            texture_dictionary_pointer,
            "TextureDictionary",
            "TextureDictionary",
            64,
        )
        shader_array_node = add_graph_pointer(
            resource_map,
            payload_view,
            layout,
            shader_group_node.id,
            "Shaders",
            shader_pointer_array,
            "PointerArray",
            "ShaderFX pointer array",
            shader_count * 8,
        )
        shader_array_validation = resource_map.boundary_validations[-1]
        if shader_array_node is not None and shader_array_validation.payload_offset is not None:
            shader_pointers = read_pointer_array(payload_view, shader_array_validation.payload_offset, shader_count)
            for shader_index, shader_pointer in enumerate(shader_pointers):
                add_graph_pointer(
                    resource_map,
                    payload_view,
                    layout,
                    shader_array_node.id,
                    f"ShaderFX[{shader_index}]",
                    shader_pointer,
                    "ShaderFX",
                    f"ShaderFX[{shader_index}]",
                    48,
                )

    for model_list in model_lists:
        list_node = add_graph_pointer(
            resource_map,
            payload_view,
            layout,
            drawable_node.id,
            f"DrawableModels{model_list.lod.title().replace('_', '')}",
            model_list.pointer,
            "DrawableModelList",
            f"DrawableModels {model_list.lod}",
            16 if model_list.pointer else 0,
        )
        if list_node is None or model_list.pointer_array_payload_offset is None:
            continue
        array_node = add_graph_pointer(
            resource_map,
            payload_view,
            layout,
            list_node.id,
            "PointerArray",
            model_list.pointer_array,
            "PointerArray",
            f"{model_list.lod} model pointer array",
            model_list.count * 8,
        )
        if array_node is None:
            continue
        for model_index, model_pointer in enumerate(model_list.model_pointers):
            model_node = add_graph_pointer(
                resource_map,
                payload_view,
                layout,
                array_node.id,
                f"Model[{model_index}]",
                model_pointer,
                "DrawableModel",
                f"{model_list.lod} model[{model_index}]",
                48,
            )
            if model_node is None or model_node.payload_offset is None:
                continue
            model_offset = model_node.payload_offset
            geometries_pointer = payload_view.u64(model_offset + 0x08)
            geometries_count = payload_view.u16(model_offset + 0x10)
            bounds_pointer = payload_view.u64(model_offset + 0x18)
            shader_mapping_pointer = payload_view.u64(model_offset + 0x20)
            add_graph_pointer(
                resource_map,
                payload_view,
                layout,
                model_node.id,
                "ShaderMapping",
                shader_mapping_pointer,
                "ShaderMapping",
                f"{model_list.lod} model[{model_index}] shader mapping",
                geometries_count * 2,
            )
            add_graph_pointer(
                resource_map,
                payload_view,
                layout,
                model_node.id,
                "Bounds",
                bounds_pointer,
                "Bounds",
                f"{model_list.lod} model[{model_index}] bounds",
                (geometries_count + (1 if geometries_count > 1 else 0)) * 32,
            )
            geometry_array_node = add_graph_pointer(
                resource_map,
                payload_view,
                layout,
                model_node.id,
                "Geometries",
                geometries_pointer,
                "PointerArray",
                f"{model_list.lod} model[{model_index}] geometry pointer array",
                geometries_count * 8,
            )
            geometry_array_validation = resource_map.boundary_validations[-1]
            if geometry_array_node is None or geometry_array_validation.payload_offset is None:
                continue
            geometry_pointers = read_pointer_array(payload_view, geometry_array_validation.payload_offset, geometries_count)
            for geometry_index, geometry_pointer in enumerate(geometry_pointers):
                geometry_node = add_graph_pointer(
                    resource_map,
                    payload_view,
                    layout,
                    geometry_array_node.id,
                    f"Geometry[{geometry_index}]",
                    geometry_pointer,
                    "DrawableGeometry",
                    f"{model_list.lod} model[{model_index}] geometry[{geometry_index}]",
                    0x98,
                )
                if geometry_node is None or geometry_node.payload_offset is None:
                    continue
                geometry_offset = geometry_node.payload_offset
                vertex_buffer_pointer = payload_view.u64(geometry_offset + 0x18)
                index_buffer_pointer = payload_view.u64(geometry_offset + 0x38)
                bone_ids_pointer = payload_view.u64(geometry_offset + 0x68)
                bone_ids_count = payload_view.u16(geometry_offset + 0x72)
                vertex_data_pointer = payload_view.u64(geometry_offset + 0x78)
                add_graph_pointer(
                    resource_map,
                    payload_view,
                    layout,
                    geometry_node.id,
                    "VertexBuffer",
                    vertex_buffer_pointer,
                    "VertexBuffer",
                    f"{geometry_node.label} vertex buffer",
                    128,
                )
                add_graph_pointer(
                    resource_map,
                    payload_view,
                    layout,
                    geometry_node.id,
                    "IndexBuffer",
                    index_buffer_pointer,
                    "IndexBuffer",
                    f"{geometry_node.label} index buffer",
                    96,
                )
                add_graph_pointer(
                    resource_map,
                    payload_view,
                    layout,
                    geometry_node.id,
                    "BoneIds",
                    bone_ids_pointer,
                    "BoneIds",
                    f"{geometry_node.label} bone ids",
                    bone_ids_count * 2,
                )
                add_graph_pointer(
                    resource_map,
                    payload_view,
                    layout,
                    geometry_node.id,
                    "VertexData",
                    vertex_data_pointer,
                    "VertexData",
                    f"{geometry_node.label} vertex data",
                    16,
                )
    if ctx:
        ctx.add_trace(
            "resource_map",
            f"nodes={len(resource_map.nodes)}, edges={len(resource_map.edges)}, validations={len(resource_map.boundary_validations)}",
        )
    return resource_map


def parse_ydr_info(data: bytes, header: Rsc7Header | Rsc8Header, ctx: ParseContext | None = None) -> YdrInfo:
    payload, encoding = get_resource_payload(data, header)
    if header.system_flags is None or header.graphics_flags is None:
        raise ParseError("resource header does not expose decoded system/graphics page sizes")
    system_size = header.system_flags.decoded_size
    graphics_size = header.graphics_flags.decoded_size
    layout = build_resource_layout(system_size, graphics_size)
    payload_view = BinaryView(payload)
    expected_size = system_size + graphics_size
    if expected_size == 0:
        raise ParseError("RSC7 page flags declare zero resource size")
    if ctx:
        ctx.add_trace(
            "ydr.payload",
            f"encoding={encoding}, system_size={system_size}, graphics_size={graphics_size}",
            offset=header.payload_offset,
            length=len(payload),
        )
        ctx.add_hex_window(payload_view, 0, "YDR payload start")
    payload_view.require(0, min(expected_size, 168), "YDR drawable base")

    # DrawableBase starts after ResourceFileBase. Offsets are from the resource
    # payload, matching ResourceDataReader's 0x50000000 system base.
    lod_pointer_offsets = {
        "high": 0x50,
        "medium": 0x58,
        "low": 0x60,
        "very_low": 0x68,
    }

    model_lists: list[DrawableModelListInfo] = []
    seen_pointers: set[int] = set()
    for label, offset in lod_pointer_offsets.items():
        pointer = payload_view.u64(offset)
        if ctx:
            ctx.add_trace("ydr.drawable_base", f"{label} model list pointer=0x{pointer:016X}", offset, 8)
        if pointer == 0:
            model_lists.append(
                DrawableModelListInfo(
                    lod=label,
                    owner_field_offset=offset,
                    pointer=0,
                    payload_offset=None,
                    pointer_array=0,
                    pointer_array_payload_offset=None,
                    count=0,
                    capacity=0,
                )
            )
            continue
        if pointer in seen_pointers:
            model_lists.append(
                DrawableModelListInfo(
                    lod=label,
                    owner_field_offset=offset,
                    pointer=pointer,
                    payload_offset=None,
                    pointer_array=0,
                    pointer_array_payload_offset=None,
                    count=0,
                    capacity=0,
                    is_duplicate_pointer=True,
                )
            )
            continue
        seen_pointers.add(pointer)
        model_lists.append(
            read_resource_pointer_list(
                payload_view,
                pointer,
                layout=layout,
                label=f"DrawableModels{label.title().replace('_', '')}",
                lod=label,
                owner_field_offset=offset,
                ctx=ctx,
            )
        )

    resource_map = build_ydr_resource_map(payload_view, layout, model_lists, ctx=ctx)
    return YdrInfo(
        payload_encoding=encoding,
        resource_layout=layout,
        model_lists=model_lists,
        resource_map=resource_map,
    )


def field_ranges(fields: list[StructureFieldSnapshot]) -> list[range]:
    return [range(field.offset, field.offset + field.size) for field in fields]


def count_unknown_nonzero_bytes(data: bytes, fields: list[StructureFieldSnapshot]) -> int:
    known_offsets = set()
    for item in field_ranges(fields):
        known_offsets.update(item)
    return sum(1 for offset, byte in enumerate(data) if offset not in known_offsets and byte != 0)


def snapshot_u16(view: BinaryView, structure: str, base: int, offset: int, label: str, meaning: str) -> StructureFieldSnapshot:
    return StructureFieldSnapshot(structure, label, offset, 2, str(view.u16(base + offset)), meaning, "observed")


def snapshot_u32(view: BinaryView, structure: str, base: int, offset: int, label: str, meaning: str) -> StructureFieldSnapshot:
    return StructureFieldSnapshot(structure, label, offset, 4, str(view.u32(base + offset)), meaning, "observed")


def snapshot_u64_ptr(view: BinaryView, structure: str, base: int, offset: int, label: str, meaning: str) -> StructureFieldSnapshot:
    return StructureFieldSnapshot(structure, label, offset, 8, f"0x{view.u64(base + offset):016X}", meaning, "observed-pointer")


STRUCTURE_FIELD_READERS: dict[str, list[tuple[int, int, str, str, str]]] = {
    "Drawable": [
        (0x00, 4, "signature_or_vft", "u32", "Drawable object signature/vtable marker"),
        (0x04, 4, "block_map_or_version", "u32", "Drawable block-map/version field"),
        (0x10, 8, "shader_group", "ptr", "Pointer to ShaderGroup"),
        (0x18, 8, "skeleton", "ptr", "Pointer to Skeleton"),
        (0x50, 8, "models_high", "ptr", "Pointer to high LOD model list"),
        (0x58, 8, "models_medium", "ptr", "Pointer to medium LOD model list"),
        (0x60, 8, "models_low", "ptr", "Pointer to low LOD model list"),
        (0x68, 8, "models_very_low", "ptr", "Pointer to very-low LOD model list"),
        (0x90, 8, "joints", "ptr", "Pointer to joints/skeleton mapping"),
        (0xA0, 8, "models_active", "ptr", "Pointer to active/default drawable model list"),
    ],
    "DrawableModel": [
        (0x00, 4, "signature_or_vft", "u32", "DrawableModel object signature/vtable marker"),
        (0x04, 4, "block_map_or_version", "u32", "DrawableModel block-map/version field"),
        (0x08, 8, "geometries", "ptr", "Pointer to geometry pointer array"),
        (0x10, 2, "geometry_count", "u16", "Geometry count"),
        (0x12, 2, "geometry_capacity", "u16", "Geometry capacity"),
        (0x18, 8, "bounds", "ptr", "Pointer to bounds data"),
        (0x20, 8, "shader_mapping", "ptr", "Pointer to geometry shader ID mapping"),
        (0x2C, 2, "flags", "u16", "Model flags"),
        (0x2E, 2, "geometry_count_b", "u16", "Second observed geometry count field"),
    ],
    "DrawableGeometry": [
        (0x00, 4, "signature_or_vft", "u32", "DrawableGeometry object signature/vtable marker"),
        (0x04, 4, "block_map_or_version", "u32", "DrawableGeometry block-map/version field"),
        (0x18, 8, "vertex_buffer", "ptr", "Pointer to VertexBuffer"),
        (0x38, 8, "index_buffer", "ptr", "Pointer to IndexBuffer"),
        (0x58, 4, "index_count", "u32", "Index count"),
        (0x5C, 4, "triangle_count", "u32", "Triangle count"),
        (0x60, 2, "vertex_count_u16", "u16", "Observed 16-bit vertex count or count clamp"),
        (0x62, 2, "primitive_type", "u16", "Observed primitive/topology field"),
        (0x68, 8, "bone_ids", "ptr", "Pointer to bone ID list"),
        (0x70, 2, "vertex_stride", "u16", "Observed vertex stride field"),
        (0x78, 8, "vertex_data", "ptr", "Pointer to vertex stream data"),
    ],
    "VertexBuffer": [
        (0x00, 4, "signature_or_vft", "u32", "VertexBuffer object signature/vtable marker"),
        (0x04, 4, "block_map_or_version", "u32", "VertexBuffer block-map/version field"),
        (0x08, 2, "vertex_stride", "u16", "Vertex stride"),
        (0x10, 8, "data_pointer_1", "ptr", "Pointer to vertex stream data"),
        (0x18, 4, "vertex_count", "u32", "Vertex count"),
        (0x20, 8, "data_pointer_2", "ptr", "Second observed pointer to vertex stream data"),
    ],
    "IndexBuffer": [
        (0x00, 4, "signature_or_vft", "u32", "IndexBuffer object signature/vtable marker"),
        (0x04, 4, "block_map_or_version", "u32", "IndexBuffer block-map/version field"),
        (0x08, 4, "index_count", "u32", "Index count"),
        (0x10, 8, "indices", "ptr", "Pointer to index stream data"),
    ],
    "ShaderGroup": [
        (0x00, 4, "signature_or_vft", "u32", "ShaderGroup object signature/vtable marker"),
        (0x04, 4, "block_map_or_version", "u32", "ShaderGroup block-map/version field"),
        (0x08, 8, "texture_dictionary", "ptr", "Pointer to TextureDictionary"),
        (0x10, 8, "shaders", "ptr", "Pointer to ShaderFX pointer array"),
        (0x18, 2, "shader_count", "u16", "Shader count"),
        (0x1A, 2, "shader_capacity", "u16", "Shader capacity"),
    ],
    "TextureDictionary": [
        (0x00, 4, "signature_or_hash", "u32", "Texture dictionary signature/hash field"),
        (0x04, 4, "version_or_block", "u32", "Texture dictionary version/block field"),
        (0x08, 8, "textures", "ptr", "Pointer to texture pointer array or native dictionary payload"),
        (0x10, 4, "texture_count", "u32", "Texture count"),
        (0x14, 4, "texture_capacity", "u32", "Texture capacity"),
    ],
    "ShaderFX": [
        (0x00, 8, "shader_hash", "ptr", "Observed shader hash/name field"),
        (0x08, 4, "draw_bucket", "u32", "Draw bucket"),
        (0x0C, 4, "parameter_count", "u32", "Shader parameter count"),
        (0x26, 8, "parameter_table", "ptr", "Pointer to serialized parameter table in this packer"),
    ],
}


def snapshot_structure_fields(
    view: BinaryView,
    structure_type: str,
    base: int,
    available_length: int,
) -> list[StructureFieldSnapshot]:
    fields: list[StructureFieldSnapshot] = []
    for offset, size, label, kind, meaning in STRUCTURE_FIELD_READERS.get(structure_type, []):
        if offset + size > available_length:
            continue
        if kind == "u16":
            fields.append(snapshot_u16(view, structure_type, base, offset, label, meaning))
        elif kind == "u32":
            fields.append(snapshot_u32(view, structure_type, base, offset, label, meaning))
        elif kind == "ptr":
            fields.append(snapshot_u64_ptr(view, structure_type, base, offset, label, meaning))
    return fields


def extract_ydr_structure_snapshot(path: Path) -> YdrStructureSnapshot:
    inspection = inspect_file(path, max_entries=100_000, string_limit=0)
    if not isinstance(inspection.header, (Rsc7Header, Rsc8Header)) or inspection.ydr is None:
        raise ParseError(f"{path} is not an inspectable YDR RSC7 resource")
    data = path.read_bytes()
    payload, _ = get_resource_payload(data, inspection.header)
    view = BinaryView(payload)
    resource_map = inspection.ydr.resource_map
    if resource_map is None:
        raise ParseError(f"{path} has no resource map")
    nodes: list[StructureNodeSnapshot] = []
    for node in resource_map.nodes:
        if node.payload_offset is None or node.length is None:
            continue
        if node.type not in STRUCTURE_FIELD_READERS:
            continue
        length = min(node.length, len(payload) - node.payload_offset)
        if length <= 0:
            continue
        raw = payload[node.payload_offset : node.payload_offset + length]
        fields = snapshot_structure_fields(view, node.type, node.payload_offset, length)
        nodes.append(
            StructureNodeSnapshot(
                label=node.label,
                type=node.type,
                pointer=node.pointer,
                section=node.section,
                payload_offset=node.payload_offset,
                length=node.length,
                fields=fields,
                unknown_nonzero_bytes=count_unknown_nonzero_bytes(raw, fields),
                raw_prefix=" ".join(f"{byte:02X}" for byte in raw[:32]),
            )
        )
    validations = resource_map.boundary_validations
    return YdrStructureSnapshot(
        path=str(path.resolve()),
        version=inspection.header.version,
        system_size=inspection.header.system_flags.decoded_size,
        graphics_size=inspection.header.graphics_flags.decoded_size,
        drawable_models=inspection.ydr.drawable_models,
        boundary_valid=sum(1 for item in validations if item.status == "valid"),
        boundary_null=sum(1 for item in validations if item.status == "null"),
        boundary_invalid=sum(1 for item in validations if item.status == "invalid"),
        nodes=nodes,
    )


def compare_ydr_structure_snapshots(
    known_good: YdrStructureSnapshot,
    candidate: YdrStructureSnapshot,
) -> YdrStructureComparison:
    known_nodes = {(node.type, node.label): node for node in known_good.nodes}
    candidate_nodes = {(node.type, node.label): node for node in candidate.nodes}
    rows: list[StructureComparisonRow] = []
    for key, known_node in known_nodes.items():
        candidate_node = candidate_nodes.get(key)
        if candidate_node is None:
            continue
        known_fields = {field.label: field for field in known_node.fields}
        candidate_fields = {field.label: field for field in candidate_node.fields}
        for label, known_field in known_fields.items():
            candidate_field = candidate_fields.get(label)
            candidate_value = "<missing-field>" if candidate_field is None else candidate_field.value
            rows.append(
                StructureComparisonRow(
                    structure=f"{known_node.type}:{known_node.label}",
                    label=label,
                    known_good=known_field.value,
                    candidate=candidate_value,
                    status="match" if candidate_value == known_field.value else "diff",
                )
            )
        rows.append(
            StructureComparisonRow(
                structure=f"{known_node.type}:{known_node.label}",
                label="unknown_nonzero_bytes",
                known_good=str(known_node.unknown_nonzero_bytes),
                candidate=str(candidate_node.unknown_nonzero_bytes),
                status="match" if known_node.unknown_nonzero_bytes == candidate_node.unknown_nonzero_bytes else "diff",
            )
        )
    return YdrStructureComparison(
        known_good=known_good,
        candidate=candidate,
        rows=rows,
        missing_in_candidate=[f"{type_name}:{label}" for type_name, label in sorted(set(known_nodes) - set(candidate_nodes))],
        extra_in_candidate=[f"{type_name}:{label}" for type_name, label in sorted(set(candidate_nodes) - set(known_nodes))],
    )


def print_ydr_structure_snapshot(snapshot: YdrStructureSnapshot) -> None:
    print(f"YDR structure snapshot: {snapshot.path}")
    print(f"Version: {snapshot.version}")
    print(f"System size: {snapshot.system_size}")
    print(f"Graphics size: {snapshot.graphics_size}")
    print(f"Drawable Models: {snapshot.drawable_models}")
    print(
        "Boundary validation: "
        f"valid={snapshot.boundary_valid}, null={snapshot.boundary_null}, invalid={snapshot.boundary_invalid}"
    )
    for node in snapshot.nodes:
        print(f"\n{node.type}: {node.label}")
        print(f"  pointer={node.pointer}, section={node.section}, payload_offset=0x{node.payload_offset:X}, length={node.length}")
        print(f"  raw_prefix={node.raw_prefix}")
        print(f"  unknown_nonzero_bytes={node.unknown_nonzero_bytes}")
        for field in node.fields:
            print(
                f"  +0x{field.offset:02X} {field.label} ({field.meaning}, {field.confidence}): {field.value}"
            )


def print_ydr_structure_comparison(comparison: YdrStructureComparison, only_diffs: bool = False) -> None:
    print("YDR structure comparison")
    print(f"Known good: {comparison.known_good.path}")
    print(f"Candidate:  {comparison.candidate.path}")
    header_pairs = (
        ("version", comparison.known_good.version, comparison.candidate.version),
        ("system_size", comparison.known_good.system_size, comparison.candidate.system_size),
        ("graphics_size", comparison.known_good.graphics_size, comparison.candidate.graphics_size),
        ("drawable_models", comparison.known_good.drawable_models, comparison.candidate.drawable_models),
        ("boundary_invalid", comparison.known_good.boundary_invalid, comparison.candidate.boundary_invalid),
    )
    print("\nHeader/layout")
    for label, known_value, candidate_value in header_pairs:
        status = "match" if known_value == candidate_value else "diff"
        if only_diffs and status == "match":
            continue
        print(f"  {status:5} {label}: known={known_value}, candidate={candidate_value}")
    rows = [row for row in comparison.rows if not only_diffs or row.status != "match"]
    if rows:
        print("\nStructure fields")
        for row in rows:
            print(
                f"  {row.status:5} {row.structure} + {row.label}: "
                f"known={row.known_good}, candidate={row.candidate}"
            )
    if comparison.missing_in_candidate:
        print("\nMissing in candidate")
        for item in comparison.missing_in_candidate:
            print(f"  {item}")
    if comparison.extra_in_candidate:
        print("\nExtra in candidate")
        for item in comparison.extra_in_candidate:
            print(f"  {item}")


def iter_rpf8_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() == ".rpf" else []
    return sorted(path.rglob("*.rpf"))


def scan_rpf8_path(path: Path, scan_signatures: bool = True, max_files: int | None = None) -> list[tuple[Path, Rpf8Header]]:
    results: list[tuple[Path, Rpf8Header]] = []
    for index, rpf_path in enumerate(iter_rpf8_files(path)):
        if max_files is not None and index >= max_files:
            break
        with rpf_path.open("rb") as handle:
            prefix = handle.read(256)
        if not prefix.startswith(RPF8_MAGIC):
            continue
        results.append((rpf_path, parse_rpf8_header_bytes(prefix, path=rpf_path, scan_signatures=scan_signatures)))
    return results


def print_rpf8_scan(results: list[tuple[Path, Rpf8Header]]) -> None:
    print(f"RPF8 files: {len(results)}")
    for path, header in results:
        print(f"\n{path}")
        print(f"  entries_guess={header.entry_count_guess}")
        print(f"  toc_size_guess={header.toc_size_guess}")
        print(f"  flags={header.flags_raw_hex}")
        if header.toc_transform_guess != "unknown":
            print(f"  toc_transform_guess={header.toc_transform_guess}")
            for item in header.toc_transform_evidence:
                print(f"    evidence: {item}")
        if header.nested_rpf8_offsets:
            nested = ", ".join(f"0x{offset:X}" for offset in header.nested_rpf8_offsets[:12])
            print(f"  nested_rpf8_offsets={nested}")
        if header.resource_signature_hits:
            hits = ", ".join(f"{hit.signature}@{hit.offset_hex}" for hit in header.resource_signature_hits[:12])
            print(f"  validated_raw_rsc7_hits={hits}")
        if header.toc_regions:
            print("  toc_regions:")
            for region in header.toc_regions:
                print(
                    f"    offset={region.offset_hex}, size={region.size}, entropy={region.entropy:.4f}, "
                    f"printable={region.printable_ratio:.4f}, zeros={region.zero_ratio:.4f}, "
                    f"entry16={region.entry16_plausible_ratio:.4f}, entry20={region.entry20_plausible_ratio:.4f}"
                )
                print(f"      zlib={region.zlib_status}")
                print(f"      raw_deflate={region.raw_deflate_status}")


def decode_rpf8_toc_blob(
    toc_path: Path,
    entry_count: int,
    entry_size: int = 16,
    names_offset: int | None = None,
    max_entries: int = 100_000,
) -> Rpf8TocDecodeReport:
    if entry_count < 0:
        raise ParseError("entry_count must be non-negative")
    if entry_count > max_entries:
        raise ParseError(f"entry_count {entry_count} exceeds max_entries {max_entries}")
    if entry_size not in (16, 20):
        raise ParseError("entry_size must be 16 or 20")
    data = toc_path.read_bytes()
    entries_size = entry_count * entry_size
    if len(data) < entries_size:
        raise ParseError(
            f"TOC blob is too small for {entry_count} entries of {entry_size} bytes: "
            f"need={entries_size}, got={len(data)}"
        )
    resolved_names_offset = entries_size if names_offset is None else names_offset
    if resolved_names_offset < entries_size or resolved_names_offset > len(data):
        raise ParseError("names_offset must be within the TOC blob and after the entry table")
    names = data[resolved_names_offset:]
    warnings: list[str] = []
    entropy = shannon_entropy(data[: min(len(data), max(entries_size, 4096))])
    if entropy > 7.85:
        warnings.append(
            f"TOC blob entropy is {entropy:.4f}; this still looks encrypted or compressed, so decoded entries may be invalid"
        )
    entries: list[Rpf8DecodedEntry] = []
    plausible = 0
    for index in range(entry_count):
        offset = index * entry_size
        raw = data[offset : offset + entry_size]
        name_offset_u32 = int.from_bytes(raw[0:4], "little")
        discriminator = int.from_bytes(raw[4:8], "little")
        raw_hex = raw.hex(" ").upper()
        if discriminator == 0x7FFFFF00:
            name_offset = name_offset_u32
            name = read_c_string(names, name_offset) if name_offset < len(names) else f"<invalid-name-offset:{name_offset}>"
            first_child = int.from_bytes(raw[8:12], "little")
            child_count = int.from_bytes(raw[12:16], "little")
            if first_child <= entry_count and child_count <= entry_count:
                plausible += 1
            entries.append(
                Rpf8DecodedEntry(
                    index=index,
                    kind="directory",
                    name=name,
                    name_offset=name_offset,
                    raw_hex=raw_hex,
                    first_child_index=first_child,
                    child_count=child_count,
                )
            )
            continue
        name_offset = int.from_bytes(raw[0:2], "little")
        name = read_c_string(names, name_offset) if name_offset < len(names) else f"<invalid-name-offset:{name_offset}>"
        size = int.from_bytes(raw[2:5], "little")
        file_offset_units = int.from_bytes(raw[5:8], "little") & 0x7FFFFF
        file_offset_bytes = file_offset_units * 512
        if discriminator & 0x80000000:
            system_flags_raw = int.from_bytes(raw[8:12], "little")
            graphics_flags_raw = int.from_bytes(raw[12:16], "little")
            if size > 0 and file_offset_units > 0:
                plausible += 1
            entries.append(
                Rpf8DecodedEntry(
                    index=index,
                    kind="resource",
                    name=name,
                    name_offset=name_offset & 0xFFFF,
                    raw_hex=raw_hex,
                    size=size,
                    file_offset_bytes=file_offset_bytes,
                    system_flags_hex=f"0x{system_flags_raw:08X}",
                    graphics_flags_hex=f"0x{graphics_flags_raw:08X}",
                )
            )
            continue
        file_size = int.from_bytes(raw[8:12], "little")
        if size > 0 and file_size >= size and file_offset_units > 0:
            plausible += 1
        entries.append(
            Rpf8DecodedEntry(
                index=index,
                kind="binary",
                name=name,
                name_offset=name_offset & 0xFFFF,
                raw_hex=raw_hex,
                size=size,
                file_offset_bytes=file_offset_bytes,
                child_count=file_size,
            )
        )
    plausible_ratio = ratio(plausible, entry_count)
    if entry_count and plausible_ratio < 0.25:
        warnings.append(
            f"only {plausible_ratio:.2%} of entries look plausible; check decryption, entry size, names offset, and TOC source"
        )
    return Rpf8TocDecodeReport(
        toc_path=str(toc_path.resolve()),
        entry_count=entry_count,
        entry_size=entry_size,
        names_offset=resolved_names_offset,
        names_length=len(names),
        entries=entries,
        warnings=warnings,
    )


def print_rpf8_toc_decode_report(report: Rpf8TocDecodeReport, limit: int = 100) -> None:
    print(f"Decoded RPF8 TOC: {report.toc_path}")
    print(f"Entries: {report.entry_count}")
    print(f"Entry size: {report.entry_size}")
    print(f"Names offset: 0x{report.names_offset:X}")
    print(f"Names length: {report.names_length}")
    if report.warnings:
        print("\nWarnings")
        for warning in report.warnings:
            print(f"  [warning] {warning}")
    print("\nEntries")
    for entry in report.entries[:limit]:
        print(f"  [{entry.index:04}] {entry.kind:9} {entry.name}")
        print(f"       raw={entry.raw_hex}")
        if entry.kind == "directory":
            print(f"       first_child_index={entry.first_child_index}, child_count={entry.child_count}")
        elif entry.kind == "resource":
            print(
                f"       size={entry.size}, file_offset={entry.file_offset_bytes}, "
                f"system={entry.system_flags_hex}, graphics={entry.graphics_flags_hex}"
            )
        else:
            print(f"       size={entry.size}, file_offset={entry.file_offset_bytes}, unpacked_size={entry.child_count}")
    if len(report.entries) > limit:
        print(f"  ... {len(report.entries) - limit} more entries not shown")


def find_rsc8_files(root: Path) -> list[Path]:
    paths = [root] if root.is_file() else list(root.rglob("*"))
    results: list[Path] = []
    for path in paths:
        if not path.is_file():
            continue
        if path.suffix.lower() not in RESOURCE_EXTENSIONS:
            continue
        try:
            with path.open("rb") as handle:
                magic = handle.read(4)
        except OSError:
            continue
        if magic == RSC8_MAGIC:
            results.append(path)
    return sorted(results)


def analyze_rsc8_corpus(root: Path) -> Rsc8CorpusReport:
    entries: list[Rsc8CorpusEntry] = []
    for path in find_rsc8_files(root):
        data = path.read_bytes()[:16]
        if len(data) < 16:
            continue
        word1, word2, word3 = struct.unpack_from("<III", data, 4)
        file_size = path.stat().st_size
        payload_size = max(0, file_size - 16)
        word3_high16 = (word3 >> 16) & 0xFFFF
        entries.append(
            Rsc8CorpusEntry(
                path=str(path.resolve()),
                extension=path.suffix.lower(),
                file_size=file_size,
                word1_hex=f"0x{word1:08X}",
                word2_hex=f"0x{word2:08X}",
                word3_hex=f"0x{word3:08X}",
                word1_low16=word1 & 0xFFFF,
                word1_high16=(word1 >> 16) & 0xFFFF,
                word2_low16=word2 & 0xFFFF,
                word2_high16=(word2 >> 16) & 0xFFFF,
                word3_low16=word3 & 0xFFFF,
                word3_high16=word3_high16,
                payload_size=payload_size,
                payload_units_2048_floor=payload_size // 2048,
                word3_high16_matches_2048_floor=word3_high16 == payload_size // 2048,
            )
        )
    observations: list[str] = []
    native_entries = [entry for entry in entries if entry.word1_hex == "0x01000002" and entry.word2_hex == "0x00010000"]
    if native_entries:
        observations.append(
            "native loose RSC8 samples share word1=0x01000002 and word2=0x00010000"
        )
    if native_entries and all(entry.word3_low16 == 2 for entry in native_entries):
        observations.append("native loose RSC8 samples share word3 low16=0x0002")
    if native_entries and all(entry.word3_high16_matches_2048_floor for entry in native_entries):
        observations.append("native loose RSC8 word3 high16 equals floor((file_size - 16) / 2048)")
    if len({entry.extension for entry in native_entries}) == 1 and native_entries:
        observations.append(
            f"native loose corpus currently only covers {native_entries[0].extension}; drawable-specific RSC8 semantics remain unconfirmed"
        )
    return Rsc8CorpusReport(root=str(root.resolve()), entries=entries, observations=observations)


def print_rsc8_corpus_report(report: Rsc8CorpusReport) -> None:
    print(f"RSC8 corpus: {report.root}")
    print(f"Entries: {len(report.entries)}")
    if report.observations:
        print("\nObservations")
        for observation in report.observations:
            print(f"  {observation}")
    if report.entries:
        print("\nFiles")
        for entry in report.entries:
            print(f"  {entry.path}")
            print(
                f"    size={entry.file_size}, ext={entry.extension}, "
                f"word1={entry.word1_hex}, word2={entry.word2_hex}, word3={entry.word3_hex}"
            )
            print(
                f"    word1 low/high=0x{entry.word1_low16:04X}/0x{entry.word1_high16:04X}, "
                f"word2 low/high=0x{entry.word2_low16:04X}/0x{entry.word2_high16:04X}, "
                f"word3 low/high=0x{entry.word3_low16:04X}/0x{entry.word3_high16:04X}"
            )
            print(
                f"    payload={entry.payload_size}, payload//2048={entry.payload_units_2048_floor}, "
                f"word3_high16_matches={entry.word3_high16_matches_2048_floor}"
            )


def default_native_ydr_tool_roots() -> list[Path]:
    roots = [
        Path.home() / "Desktop",
        Path.home() / "Downloads",
        Path.home() / "Documents",
        Path(r"C:\Program Files"),
        Path(r"C:\Program Files (x86)"),
        Path.home()
        / "AppData"
        / "Roaming"
        / "Blender Foundation"
        / "Blender"
        / "5.1"
        / "scripts"
        / "addons",
    ]
    return [root for root in roots if root.exists()]


def find_tool_files(roots: list[Path], names: set[str], max_hits: int = 100) -> list[Path]:
    hits: list[Path] = []
    lowered = {name.lower() for name in names}
    for root in roots:
        try:
            iterator = [root] if root.is_file() else root.rglob("*")
            for path in iterator:
                if len(hits) >= max_hits:
                    return hits
                if path.is_file() and path.name.lower() in lowered:
                    hits.append(path)
        except (OSError, PermissionError):
            continue
    return sorted(set(hits))


def file_contains(path: Path, needle: str) -> bool:
    try:
        return needle.lower() in path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def detect_native_ydr_tools(roots: list[Path] | None = None) -> NativeYdrToolReport:
    if roots is None:
        roots = default_native_ydr_tool_roots()
    findings: list[NativeYdrToolFinding] = []
    for path in find_tool_files(roots, {"CodeX.exe", "CodeWalker.exe", "OpenIV.exe"}):
        lower_name = path.name.lower()
        if path.name == "CodeX.exe":
            status = "candidate"
            reason = "CodeX is the expected legitimate comparison tool, but export capability still needs a real run."
        elif lower_name == "codewalker.exe":
            status = "candidate"
            reason = "CodeWalker can round-trip many RAGE resources; RDR2 native YDR write support must be confirmed per build."
        elif lower_name == "codex.exe":
            status = "unrelated"
            reason = "This is not Rockstar/CodeWalker CodeX; it appears to be a different application with the same name."
        else:
            status = "not-confirmed"
            reason = "OpenIV is useful for archive/resource inspection, but it is not a confirmed native RDR2 YDR writer here."
        findings.append(NativeYdrToolFinding(path.stem, str(path.resolve()), status, reason))

    addon_root = (
        Path.home()
        / "AppData"
        / "Roaming"
        / "Blender Foundation"
        / "Blender"
        / "5.1"
        / "scripts"
        / "addons"
    )
    rdr_addon = addon_root / "sollumz_rdr_dev"
    if rdr_addon.exists():
        manifest = rdr_addon / "blender_manifest.toml"
        readme = rdr_addon / "README.md"
        reason = "Installed RDR add-on is CodeWalker XML focused; no native RSC8 YDR writer was detected."
        if file_contains(manifest, "codewalker xml") or file_contains(readme, "CodeWalker"):
            reason = "Installed RDR add-on advertises CodeWalker XML import/export, not native RSC8 YDR binary writing."
        findings.append(
            NativeYdrToolFinding(
                "sollumz_rdr_dev",
                str(rdr_addon.resolve()),
                "xml-only",
                reason,
            )
        )

    sollumz = addon_root / "Sollumz"
    ydr_export = sollumz / "ydr" / "ydrexport_io.py"
    if ydr_export.exists():
        if file_contains(ydr_export, "szio.gta5"):
            status = "not-rdr2"
            reason = "Native exporter path imports szio.gta5, so it is not a confirmed RDR2 RSC8 YDR writer."
        else:
            status = "candidate"
            reason = "Sollumz native exporter exists, but the target game/resource format needs confirmation."
        findings.append(NativeYdrToolFinding("Sollumz", str(sollumz.resolve()), status, reason))

    for path in find_tool_files(roots, {"RedDeadBlend2.zip", "RedDeadBlend2.py"}):
        findings.append(
            NativeYdrToolFinding(
                "RedDeadBlend2",
                str(path.resolve()),
                "import-only-known",
                "Public 0.0.2 documentation says native RDR2 YDR/YDD import works but export does not yet.",
            )
        )

    writer_available = any(finding.status == "ready" for finding in findings)
    recommendation = (
        "No ready native RDR2 RSC8 YDR writer was detected. Use an already-exported native .ydr from a legitimate "
        "tool, install a confirmed RDR2-capable CodeX/CodeWalker build, or keep using generated candidates only for "
        "internal structure testing until a known-good sample is available."
    )
    return NativeYdrToolReport(
        roots=[str(root.resolve()) for root in roots],
        findings=findings,
        native_rdr2_ydr_writer_available=writer_available,
        recommendation=recommendation,
    )


def print_native_ydr_tool_report(report: NativeYdrToolReport) -> None:
    print("Native RDR2 YDR tool detection")
    print(f"Ready native RDR2 YDR writer: {report.native_rdr2_ydr_writer_available}")
    print("\nRoots")
    for root in report.roots:
        print(f"  {root}")
    if report.findings:
        print("\nFindings")
        for finding in report.findings:
            print(f"  {finding.name}: {finding.status}")
            print(f"    path: {finding.path}")
            print(f"    reason: {finding.reason}")
    else:
        print("\nFindings")
        print("  No CodeX, CodeWalker, OpenIV, Sollumz, Sollumz RDR, or RedDeadBlend2 install was detected.")
    print("\nRecommendation")
    print(f"  {report.recommendation}")


def hex_range(data: bytes, offset: int, length: int) -> str:
    return data[offset : offset + length].hex(" ").upper()


def compact_hex(data: bytes) -> str:
    return data.hex(" ").upper()


def classify_header_byte(offset: int, native_header: Any, generated_header: Any) -> str:
    if offset < 4:
        return "known:magic"
    if isinstance(native_header, Rsc8Header) and isinstance(generated_header, Rsc8Header):
        if 4 <= offset < 8:
            if generated_header.interpretation == "experimental-rsc8-with-rsc7-page-words":
                return "inferred:legacy-version"
            return "unknown:rsc8-word1"
        if 8 <= offset < 12:
            if generated_header.interpretation == "experimental-rsc8-with-rsc7-page-words":
                return "inferred:system-page-word"
            return "unknown:rsc8-word2"
        if 12 <= offset < 16:
            if generated_header.interpretation == "experimental-rsc8-with-rsc7-page-words":
                return "inferred:graphics-page-word"
            return "unknown:rsc8-word3"
    if 16 <= offset < 64:
        return "changing:payload-prefix"
    return "changing:sample-data"


def build_header_annotations(
    native_data: bytes,
    generated_data: bytes,
    native_inspection: Inspection,
    generated_inspection: Inspection,
    length: int,
) -> list[HeaderFieldAnnotation]:
    annotations: list[HeaderFieldAnnotation] = []
    native_header = native_inspection.header
    generated_header = generated_inspection.header
    magic_native = native_data[:4].decode("ascii", errors="replace")
    magic_generated = generated_data[:4].decode("ascii", errors="replace")
    annotations.append(
        HeaderFieldAnnotation(
            offset=0,
            length=4,
            field="magic",
            native_hex=hex_range(native_data, 0, min(4, len(native_data))),
            generated_hex=hex_range(generated_data, 0, min(4, len(generated_data))),
            status="known" if magic_native == magic_generated else "changing",
            note=f"resource magic native={magic_native!r}, generated={magic_generated!r}",
        )
    )
    if isinstance(native_header, Rsc8Header) and isinstance(generated_header, Rsc8Header) and length >= 16:
        native_words = (native_header.word1, native_header.word2, native_header.word3)
        generated_words = (generated_header.word1, generated_header.word2, generated_header.word3)
        fields = (
            ("word1", 4, "native RSC8 meaning unconfirmed; generated value is legacy-compatible version only when interpretation says so"),
            ("word2", 8, "native RSC8 meaning unconfirmed; generated value is inferred system page flags in the experimental wrapper"),
            ("word3", 12, "native RSC8 meaning unconfirmed; generated value is inferred graphics page flags in the experimental wrapper"),
        )
        for index, (field, offset, note) in enumerate(fields):
            status = "changing" if native_words[index] != generated_words[index] else "same"
            if generated_header.interpretation == "experimental-rsc8-with-rsc7-page-words":
                status = "inferred" if native_words[index] != generated_words[index] else "inferred/same"
            annotations.append(
                HeaderFieldAnnotation(
                    offset=offset,
                    length=4,
                    field=field,
                    native_hex=hex_range(native_data, offset, 4),
                    generated_hex=hex_range(generated_data, offset, 4),
                    status=status,
                    note=note,
                )
            )
    if length > 16:
        payload_len = min(length, 64) - 16
        annotations.append(
            HeaderFieldAnnotation(
                offset=16,
                length=payload_len,
                field="payload prefix",
                native_hex=hex_range(native_data, 16, payload_len),
                generated_hex=hex_range(generated_data, 16, payload_len),
                status="changing",
                note="first resource payload bytes; object type and writer layout make this expected to change",
            )
        )
    return annotations


def compare_resource_headers(native_path: Path, generated_path: Path, byte_count: int = 64) -> HeaderComparisonReport:
    if byte_count < 16 or byte_count > 64:
        raise ParseError("--bytes must be between 16 and 64")
    if not native_path.is_file():
        raise ParseError(f"native file not found: {native_path}")
    if not generated_path.is_file():
        raise ParseError(f"generated file not found: {generated_path}")
    native_data = native_path.read_bytes()[:byte_count]
    generated_data = generated_path.read_bytes()[:byte_count]
    compared = min(byte_count, len(native_data), len(generated_data))
    native_inspection = inspect_file(native_path, max_entries=100_000, string_limit=0, hex_window_size=0)
    generated_inspection = inspect_file(generated_path, max_entries=100_000, string_limit=0, hex_window_size=0)
    native_slice = native_data[:compared]
    generated_slice = generated_data[:compared]
    xor = bytes(a ^ b for a, b in zip(native_slice, generated_slice))
    byte_diffs = [
        HeaderByteDiff(
            offset=offset,
            native_hex=f"{native_slice[offset]:02X}",
            generated_hex=f"{generated_slice[offset]:02X}",
            same=native_slice[offset] == generated_slice[offset],
            label=classify_header_byte(offset, native_inspection.header, generated_inspection.header),
        )
        for offset in range(compared)
    ]
    warnings: list[str] = []
    if native_inspection.guessed_resource_type != generated_inspection.guessed_resource_type:
        warnings.append(
            "resource types differ; use this comparison for RSC8 header behavior only, not drawable field confirmation"
        )
    if isinstance(native_inspection.header, Rsc8Header) and native_inspection.header.interpretation == "raw-rsc8":
        warnings.append("native RSC8 words are still raw/unknown; do not promote them to writer constants yet")
    if isinstance(generated_inspection.header, Rsc8Header) and generated_inspection.header.interpretation != "raw-rsc8":
        warnings.append("generated RSC8 uses experimental legacy-compatible page words")
    return HeaderComparisonReport(
        native_path=str(native_path.resolve()),
        generated_path=str(generated_path.resolve()),
        native_type=native_inspection.guessed_resource_type,
        generated_type=generated_inspection.guessed_resource_type,
        native_format=native_inspection.format,
        generated_format=generated_inspection.format,
        bytes_compared=compared,
        raw_native_hex=compact_hex(native_slice),
        raw_generated_hex=compact_hex(generated_slice),
        raw_xor_hex=compact_hex(xor),
        annotations=build_header_annotations(native_slice, generated_slice, native_inspection, generated_inspection, compared),
        byte_diffs=byte_diffs,
        warnings=warnings,
    )


def print_header_comparison_report(report: HeaderComparisonReport) -> None:
    print("Resource header comparison")
    print(f"Native:    {report.native_path}")
    print(f"Generated: {report.generated_path}")
    print(f"Native format/type:    {report.native_format} / {report.native_type}")
    print(f"Generated format/type: {report.generated_format} / {report.generated_type}")
    print(f"Bytes compared: {report.bytes_compared}")
    if report.warnings:
        print("\nWarnings")
        for warning in report.warnings:
            print(f"  [warning] {warning}")
    print("\nRaw bytes")
    print(f"  native:    {report.raw_native_hex}")
    print(f"  generated: {report.raw_generated_hex}")
    print(f"  xor:       {report.raw_xor_hex}")
    print("\nAnnotated fields")
    for item in report.annotations:
        print(f"  0x{item.offset:02X}-0x{item.offset + item.length - 1:02X} {item.field}: {item.status}")
        print(f"    native:    {item.native_hex}")
        print(f"    generated: {item.generated_hex}")
        print(f"    note: {item.note}")
    print("\nByte labels")
    for start in range(0, len(report.byte_diffs), 16):
        chunk = report.byte_diffs[start : start + 16]
        native = " ".join(item.native_hex for item in chunk)
        generated = " ".join(item.generated_hex for item in chunk)
        marks = " ".join("==" if item.same else "!=" for item in chunk)
        labels = ", ".join(f"0x{item.offset:02X}:{item.label}" for item in chunk if not item.same)
        print(f"  0x{chunk[0].offset:02X}: native    {native}")
        print(f"        generated {generated}")
        print(f"        diff      {marks}")
        if labels:
            print(f"        labels    {labels}")


def page_flags_to_dict(flags: PageFlags) -> dict[str, Any]:
    return {
        "raw_hex": flags.raw_hex,
        "version_nibble": flags.version_nibble,
        "base_shift": flags.base_shift,
        "base_size": flags.base_size,
        "page_units": flags.page_units,
        "decoded_size": flags.decoded_size,
    }


def section_to_dict(section: ResourceSection) -> dict[str, Any]:
    return {
        "name": section.name,
        "virtual_base": f"0x{section.virtual_base:08X}",
        "virtual_end": f"0x{section.virtual_end:08X}",
        "payload_offset": section.payload_offset,
        "payload_end": section.payload_end,
        "size": section.size,
    }


def build_layout_metadata(path: Path) -> ResourceLayoutMetadata:
    inspection = inspect_file(path, max_entries=100_000, string_limit=0, hex_window_size=0)
    header = inspection.header
    notes: list[str] = []
    payload_encoding: str | None = None
    system_size: int | None = None
    graphics_size: int | None = None
    decoded_total_size: int | None = None
    system_section: dict[str, Any] | None = None
    graphics_section: dict[str, Any] | None = None
    payload_offset: int | None = None
    payload_size: int | None = None
    interpretation: str | None = None
    word1_hex: str | None = None
    word2_hex: str | None = None
    word3_hex: str | None = None
    if isinstance(header, Rsc8Header):
        payload_offset = header.payload_offset
        payload_size = header.payload_size
        interpretation = header.interpretation
        word1_hex = header.word1_hex
        word2_hex = header.word2_hex
        word3_hex = header.word3_hex
        decoded_total_size = header.decoded_total_size
        if header.system_flags and header.graphics_flags:
            system_size = header.system_flags.decoded_size
            graphics_size = header.graphics_flags.decoded_size
            layout = build_resource_layout(system_size, graphics_size)
            system_section = section_to_dict(layout.system)
            graphics_section = section_to_dict(layout.graphics)
            try:
                payload_encoding = get_resource_payload(path.read_bytes(), header)[1]
            except ParseError as exc:
                notes.append(f"payload decode failed: {exc}")
        else:
            notes.append("raw RSC8 page words are not decoded into system/graphics sizes yet")
    elif isinstance(header, Rsc7Header):
        payload_offset = header.payload_offset
        payload_size = header.payload_size
        interpretation = "rsc7"
        system_size = header.system_flags.decoded_size
        graphics_size = header.graphics_flags.decoded_size
        decoded_total_size = header.decoded_total_size
        layout = build_resource_layout(system_size, graphics_size)
        system_section = section_to_dict(layout.system)
        graphics_section = section_to_dict(layout.graphics)
        try:
            payload_encoding = get_resource_payload(path.read_bytes(), header)[1]
        except ParseError as exc:
            notes.append(f"payload decode failed: {exc}")
    return ResourceLayoutMetadata(
        path=str(path.resolve()),
        format=inspection.format,
        resource_type=inspection.guessed_resource_type,
        file_size=inspection.file_size,
        payload_offset=payload_offset,
        payload_size=payload_size,
        interpretation=interpretation,
        word1_hex=word1_hex,
        word2_hex=word2_hex,
        word3_hex=word3_hex,
        system_size=system_size,
        graphics_size=graphics_size,
        decoded_total_size=decoded_total_size,
        payload_encoding=payload_encoding,
        system_section=system_section,
        graphics_section=graphics_section,
        notes=notes,
    )


def build_page_semantics(file_role: str, path: Path) -> list[PageSemanticAnnotation]:
    inspection = inspect_file(path, max_entries=100_000, string_limit=0, hex_window_size=0)
    header = inspection.header
    annotations: list[PageSemanticAnnotation] = []
    if isinstance(header, Rsc8Header):
        words = (("word1", 4, header.word1, None), ("word2", 8, header.word2, header.system_flags), ("word3", 12, header.word3, header.graphics_flags))
        for field, offset, value, flags in words:
            if field == "word1":
                if header.legacy_version is not None:
                    status = "inferred"
                    note = "generated experimental wrapper treats word1 as legacy-compatible version"
                else:
                    status = "unknown"
                    note = "native RSC8 word1 meaning is not confirmed"
                decoded = {"legacy_version": header.legacy_version} if header.legacy_version is not None else None
            else:
                if flags is not None:
                    status = "inferred"
                    note = f"{field} decodes as legacy-compatible page flags in this parser"
                    decoded = page_flags_to_dict(flags)
                else:
                    status = "unknown"
                    note = f"native RSC8 {field} page/layout semantics are not confirmed; legacy decode is shown only as a probe"
                    decoded = {"legacy_decode_if_applied": page_flags_to_dict(decode_page_flags(value))}
            annotations.append(
                PageSemanticAnnotation(
                    file_role=file_role,
                    field=field,
                    offset=offset,
                    raw_hex=f"0x{value:08X}",
                    status=status,
                    decoded=decoded,
                    note=note,
                )
            )
    elif isinstance(header, Rsc7Header):
        for field, offset, flags in (("system_flags", 8, header.system_flags), ("graphics_flags", 12, header.graphics_flags)):
            annotations.append(
                PageSemanticAnnotation(
                    file_role=file_role,
                    field=field,
                    offset=offset,
                    raw_hex=flags.raw_hex,
                    status="known",
                    decoded=page_flags_to_dict(flags),
                    note="RSC7 page flags are decoded by the existing page-flag model",
                )
            )
    return annotations


def mutate_u32(data: bytes, offset: int, value: int) -> bytes:
    mutable = bytearray(data)
    struct.pack_into("<I", mutable, offset, value)
    return bytes(mutable)


def mutation_probe(data: bytes, target: str, mutation: str, offset: int, new_value: int) -> ControlledMutationResult:
    original = struct.unpack_from("<I", data, offset)[0]
    mutated = mutate_u32(data, offset, new_value)
    try:
        header = parse_rsc8(BinaryView(mutated))
        system_size = header.system_flags.decoded_size if header.system_flags else None
        graphics_size = header.graphics_flags.decoded_size if header.graphics_flags else None
        decoded_total_size = header.decoded_total_size
        outcome = "decoded" if decoded_total_size is not None else "raw-only"
        note = "mutation still matched legacy-compatible page-word heuristic" if decoded_total_size is not None else "mutation did not expose decodable system/graphics layout"
        interpretation = header.interpretation
    except ParseError as exc:
        system_size = None
        graphics_size = None
        decoded_total_size = None
        outcome = "parse-error"
        note = str(exc)
        interpretation = None
    return ControlledMutationResult(
        target=target,
        mutation=mutation,
        offset=offset,
        original_hex=f"0x{original:08X}",
        mutated_hex=f"0x{new_value:08X}",
        interpretation=interpretation,
        system_size=system_size,
        graphics_size=graphics_size,
        decoded_total_size=decoded_total_size,
        outcome=outcome,
        note=note,
    )


def mutation_probe_words(data: bytes, target: str, mutation: str, words: tuple[int, int, int]) -> ControlledMutationResult:
    mutated = bytearray(data)
    original_words = struct.unpack_from("<III", mutated, 4)
    struct.pack_into("<III", mutated, 4, *words)
    try:
        header = parse_rsc8(BinaryView(bytes(mutated)))
        system_size = header.system_flags.decoded_size if header.system_flags else None
        graphics_size = header.graphics_flags.decoded_size if header.graphics_flags else None
        decoded_total_size = header.decoded_total_size
        outcome = "decoded" if decoded_total_size is not None else "raw-only"
        note = "combined words matched legacy-compatible page-word heuristic" if decoded_total_size is not None else "combined words remained raw RSC8 under current parser"
        interpretation = header.interpretation
    except ParseError as exc:
        system_size = None
        graphics_size = None
        decoded_total_size = None
        outcome = "parse-error"
        note = str(exc)
        interpretation = None
    return ControlledMutationResult(
        target=target,
        mutation=mutation,
        offset=4,
        original_hex=" ".join(f"0x{word:08X}" for word in original_words),
        mutated_hex=" ".join(f"0x{word:08X}" for word in words),
        interpretation=interpretation,
        system_size=system_size,
        graphics_size=graphics_size,
        decoded_total_size=decoded_total_size,
        outcome=outcome,
        note=note,
    )


def controlled_layout_mutations(native_path: Path, generated_path: Path) -> list[ControlledMutationResult]:
    native_data = native_path.read_bytes()
    generated_data = generated_path.read_bytes()
    if len(native_data) < 16 or len(generated_data) < 16:
        return []
    native_header = parse_rsc8(BinaryView(native_data)) if native_data[:4] == RSC8_MAGIC else None
    generated_header = parse_rsc8(BinaryView(generated_data)) if generated_data[:4] == RSC8_MAGIC else None
    if native_header is None or generated_header is None:
        return []
    return [
        mutation_probe_words(
            generated_data,
            "generated",
            "words1-3 := native.words1-3",
            (native_header.word1, native_header.word2, native_header.word3),
        ),
        mutation_probe_words(
            native_data,
            "native",
            "words1-3 := generated.words1-3",
            (generated_header.word1, generated_header.word2, generated_header.word3),
        ),
        mutation_probe(generated_data, "generated", "word1 := native.word1", 4, native_header.word1),
        mutation_probe(generated_data, "generated", "word2 := native.word2", 8, native_header.word2),
        mutation_probe(generated_data, "generated", "word3 := native.word3", 12, native_header.word3),
        mutation_probe(generated_data, "generated", "word2 := 0", 8, 0),
        mutation_probe(generated_data, "generated", "word3 := 0", 12, 0),
        mutation_probe(native_data, "native", "word1 := generated.word1", 4, generated_header.word1),
        mutation_probe(native_data, "native", "word2 := generated.word2", 8, generated_header.word2),
        mutation_probe(native_data, "native", "word3 := generated.word3", 12, generated_header.word3),
    ]


def compare_resource_layouts(native_path: Path, generated_path: Path, byte_count: int = 64) -> ResourceLayoutComparisonReport:
    header = compare_resource_headers(native_path, generated_path, byte_count=byte_count)
    native_layout = build_layout_metadata(native_path)
    generated_layout = build_layout_metadata(generated_path)
    warnings = list(header.warnings)
    if native_layout.system_size is None or native_layout.graphics_size is None:
        warnings.append("native resource layout sizes are unknown because native RSC8 page semantics are not decoded yet")
    if generated_layout.system_size is not None and generated_layout.graphics_size is not None:
        warnings.append("generated layout sizes are inferred from experimental RSC7-compatible page words")
    return ResourceLayoutComparisonReport(
        header=header,
        native_layout=native_layout,
        generated_layout=generated_layout,
        page_semantics=[
            *build_page_semantics("native", native_path),
            *build_page_semantics("generated", generated_path),
        ],
        mutations=controlled_layout_mutations(native_path, generated_path),
        warnings=warnings,
    )


def print_layout_metadata(label: str, metadata: ResourceLayoutMetadata) -> None:
    print(f"{label}: {metadata.path}")
    print(f"  format/type: {metadata.format} / {metadata.resource_type}")
    print(f"  file_size={metadata.file_size}, payload_offset={metadata.payload_offset}, payload_size={metadata.payload_size}")
    print(f"  interpretation={metadata.interpretation}")
    if metadata.word1_hex is not None:
        print(f"  words: word1={metadata.word1_hex}, word2={metadata.word2_hex}, word3={metadata.word3_hex}")
    print(
        f"  layout: system={metadata.system_size}, graphics={metadata.graphics_size}, "
        f"decoded_total={metadata.decoded_total_size}, payload_encoding={metadata.payload_encoding}"
    )
    if metadata.system_section:
        print(f"  system section: {metadata.system_section}")
    if metadata.graphics_section:
        print(f"  graphics section: {metadata.graphics_section}")
    for note in metadata.notes:
        print(f"  note: {note}")


def print_resource_layout_comparison_report(report: ResourceLayoutComparisonReport) -> None:
    print("Resource layout comparison")
    print(f"Bytes compared: {report.header.bytes_compared}")
    if report.warnings:
        print("\nWarnings")
        for warning in dict.fromkeys(report.warnings):
            print(f"  [warning] {warning}")
    print("\nRaw header bytes")
    print(f"  native:    {report.header.raw_native_hex}")
    print(f"  generated: {report.header.raw_generated_hex}")
    print(f"  xor:       {report.header.raw_xor_hex}")
    print("\nLayout metadata")
    print_layout_metadata("Native", report.native_layout)
    print_layout_metadata("Generated", report.generated_layout)
    print("\nAnnotated page semantics")
    for item in report.page_semantics:
        decoded = "" if item.decoded is None else f" decoded={item.decoded}"
        print(
            f"  {item.file_role} 0x{item.offset:02X} {item.field}={item.raw_hex}: "
            f"{item.status}{decoded}"
        )
        print(f"    note: {item.note}")
    print("\nControlled mutations")
    for item in report.mutations:
        print(
            f"  {item.target} {item.mutation} @0x{item.offset:02X}: "
            f"{item.original_hex} -> {item.mutated_hex}"
        )
        print(
            f"    outcome={item.outcome}, interpretation={item.interpretation}, "
            f"system={item.system_size}, graphics={item.graphics_size}, decoded_total={item.decoded_total_size}"
        )
        print(f"    note: {item.note}")


def object_domain_for_type(type_name: str) -> str:
    graphics_types = {"VertexData", "IndexData", "TexturePayload"}
    system_types = {
        "Drawable",
        "DrawableModel",
        "DrawableGeometry",
        "DrawableModelList",
        "ShaderGroup",
        "TextureDictionary",
        "ShaderFX",
        "ShaderParameterTable",
        "VertexBuffer",
        "IndexBuffer",
        "PointerArray",
    }
    if type_name in graphics_types:
        return "graphics"
    if type_name in system_types:
        return "system"
    return "shared/unknown"


def alignment_for_offset(offset: int | None) -> int | None:
    if offset is None:
        return None
    if offset == 0:
        return 0
    alignment = 1
    while offset % (alignment * 2) == 0:
        alignment *= 2
    return alignment


def generated_report_from_manifest(path: Path) -> BinaryWriteReport | None:
    resolved = str(path.resolve())
    for manifest in path.resolve().parents:
        manifest_path = manifest / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            items = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            writer = item.get("writer") if isinstance(item, dict) else None
            if not isinstance(writer, dict):
                continue
            if writer.get("output_path") != resolved and item.get("ydr") != resolved:
                continue
            objects = [BinaryObjectRecord(**obj) for obj in writer.get("objects", [])]
            fixups = [BinaryFixupRecord(**fixup) for fixup in writer.get("fixups", [])]
            return BinaryWriteReport(
                output_path=writer.get("output_path", resolved),
                version=int(writer.get("version", 0)),
                system_size=int(writer.get("system_size", 0)),
                graphics_size=int(writer.get("graphics_size", 0)),
                objects=objects,
                fixups=fixups,
                warnings=list(writer.get("warnings", [])),
            )
    return None


def relocation_offset_group(offset: int | None, owner_section: str | None) -> str:
    if owner_section in {"system", "graphics"}:
        return owner_section
    if offset is None:
        return "unknown"
    return "offset-known-domain-unknown"


def summarize_relocations(path: Path) -> RelocationSummary:
    report = generated_report_from_manifest(path)
    entries: list[RelocationEntry] = []
    warnings: list[str] = []
    source = "generated-manifest" if report else "resource-map-inferred"
    system_size = 0
    graphics_size = 0
    if report is not None:
        object_by_name = {item.name: item for item in report.objects}
        pointer_counts: dict[int, int] = {}
        for item in report.objects:
            if item.pointer:
                pointer_counts[item.pointer] = pointer_counts.get(item.pointer, 0) + 1
        duplicate_pointers = [f"0x{pointer:016X}" for pointer, count in pointer_counts.items() if count > 1]
        if duplicate_pointers:
            warnings.append(f"duplicate generated object pointers detected: {', '.join(duplicate_pointers)}")
        system_size = report.system_size
        graphics_size = report.graphics_size
        for fixup in report.fixups:
            owner = object_by_name.get(fixup.owner)
            target = object_by_name.get(fixup.target)
            owner_section = owner.section if owner else None
            target_section = target.section if target else None
            entries.append(
                RelocationEntry(
                    source=source,
                    owner=fixup.owner,
                    owner_type=owner.type if owner else None,
                    field=fixup.field,
                    offset=fixup.offset,
                    offset_group=relocation_offset_group(fixup.offset, owner_section),
                    target=fixup.target,
                    target_type=target.type if target else None,
                    pointer=fixup.pointer_hex,
                    owner_section=owner_section,
                    target_section=target_section,
                    page_crossing=bool(owner_section and target_section and owner_section != target_section),
                    confidence="HIGH_CONFIDENCE",
                )
            )
    else:
        inspection = inspect_file(path, max_entries=100_000, string_limit=0, hex_window_size=0)
        if not inspection.ydr or not inspection.ydr.resource_map:
            raise ParseError(f"{path} does not expose a resource map for relocation inference")
        if isinstance(inspection.header, (Rsc7Header, Rsc8Header)) and inspection.header.system_flags and inspection.header.graphics_flags:
            system_size = inspection.header.system_flags.decoded_size
            graphics_size = inspection.header.graphics_flags.decoded_size
        node_by_id = {node.id: node for node in inspection.ydr.resource_map.nodes}
        for edge in inspection.ydr.resource_map.edges:
            if edge.status != "valid":
                continue
            owner = node_by_id.get(edge.source)
            target = node_by_id.get(edge.target)
            owner_section = owner.section if owner else None
            target_section = target.section if target else None
            entries.append(
                RelocationEntry(
                    source=source,
                    owner=owner.label if owner else edge.source,
                    owner_type=owner.type if owner else None,
                    field=edge.field,
                    offset=None,
                    offset_group=relocation_offset_group(None, owner_section),
                    target=target.label if target else edge.target,
                    target_type=target.type if target else None,
                    pointer=edge.pointer,
                    owner_section=owner_section,
                    target_section=target_section,
                    page_crossing=bool(owner_section and target_section and owner_section != target_section),
                    confidence="INFERRED",
                )
            )
        warnings.append("relocations inferred from pointer graph; native relocation/fixup table format is not confirmed")
    by_section_pair: dict[str, int] = {}
    by_owner_type: dict[str, int] = {}
    by_target_type: dict[str, int] = {}
    for entry in entries:
        section_pair = f"{entry.owner_section or '?'}->{entry.target_section or '?'}"
        by_section_pair[section_pair] = by_section_pair.get(section_pair, 0) + 1
        owner_type = entry.owner_type or "unknown"
        target_type = entry.target_type or "unknown"
        by_owner_type[owner_type] = by_owner_type.get(owner_type, 0) + 1
        by_target_type[target_type] = by_target_type.get(target_type, 0) + 1
    size_by_domain = {
        "system": max(system_size, 1),
        "graphics": max(graphics_size, 1),
        "total": max(system_size + graphics_size, 1),
    }
    density_per_kb = {
        "system": sum(1 for item in entries if item.owner_section == "system") / (size_by_domain["system"] / 1024),
        "graphics": sum(1 for item in entries if item.owner_section == "graphics") / (size_by_domain["graphics"] / 1024),
        "total": len(entries) / (size_by_domain["total"] / 1024),
    }
    return RelocationSummary(
        path=str(path.resolve()),
        source=source,
        total=len(entries),
        exact_offsets=sum(1 for item in entries if item.offset is not None),
        inferred_offsets=sum(1 for item in entries if item.offset is None),
        page_crossing=sum(1 for item in entries if item.page_crossing),
        by_section_pair=by_section_pair,
        by_owner_type=by_owner_type,
        by_target_type=by_target_type,
        density_per_kb=density_per_kb,
        entries=entries,
        warnings=warnings,
    )


def relocation_signature(entry: RelocationEntry) -> tuple[str | None, str, str | None, bool]:
    return (entry.owner_type, entry.field, entry.target_type, entry.page_crossing)


def compare_relocations(left_path: Path, right_path: Path) -> RelocationComparisonReport:
    left = summarize_relocations(left_path)
    right = summarize_relocations(right_path)
    left_sigs = [relocation_signature(item) for item in left.entries]
    right_sigs = [relocation_signature(item) for item in right.entries]
    missing: list[RelocationEntry] = []
    extra: list[RelocationEntry] = []
    remaining_right = right_sigs.copy()
    for entry, sig in zip(left.entries, left_sigs):
        if sig in remaining_right:
            remaining_right.remove(sig)
        else:
            missing.append(entry)
    remaining_left = left_sigs.copy()
    for entry, sig in zip(right.entries, right_sigs):
        if sig in remaining_left:
            remaining_left.remove(sig)
        else:
            extra.append(entry)
    ordering_differences: list[str] = []
    for index, (left_sig, right_sig) in enumerate(zip(left_sigs, right_sigs)):
        if left_sig != right_sig:
            ordering_differences.append(f"index {index}: left={left_sig}, right={right_sig}")
    section_keys = set(left.by_section_pair) | set(right.by_section_pair)
    section_pair_deltas = {
        key: right.by_section_pair.get(key, 0) - left.by_section_pair.get(key, 0)
        for key in sorted(section_keys)
    }
    warnings = [*left.warnings, *right.warnings]
    if left.source != right.source:
        warnings.append("left/right relocation sources differ; exact writer fixups and inferred graph edges are not equivalent evidence")
    return RelocationComparisonReport(
        left=left,
        right=right,
        missing_in_right=missing,
        extra_in_right=extra,
        ordering_differences=ordering_differences,
        section_pair_deltas=section_pair_deltas,
        warnings=warnings,
    )


def print_relocation_summary(summary: RelocationSummary) -> None:
    print(f"Relocation summary: {summary.path}")
    print(f"Source: {summary.source}")
    print(
        f"Total={summary.total}, exact_offsets={summary.exact_offsets}, "
        f"inferred_offsets={summary.inferred_offsets}, page_crossing={summary.page_crossing}"
    )
    print(f"Density per KB: {summary.density_per_kb}")
    print(f"Section pairs: {summary.by_section_pair}")
    print(f"Owner types: {summary.by_owner_type}")
    print(f"Target types: {summary.by_target_type}")
    for warning in summary.warnings:
        print(f"  [warning] {warning}")
    print("\nEntries")
    for entry in summary.entries:
        offset = "<inferred>" if entry.offset is None else f"0x{entry.offset:X}"
        print(
            f"  {entry.owner_type or '?'}:{entry.owner} + {entry.field} @ {offset} "
            f"-> {entry.target_type or '?'}:{entry.target} {entry.pointer} "
            f"{entry.owner_section}->{entry.target_section} crossing={entry.page_crossing} {entry.confidence}"
        )


def print_relocation_comparison(report: RelocationComparisonReport) -> None:
    print("Relocation comparison")
    print(f"Left:  {report.left.path}")
    print(f"Right: {report.right.path}")
    if report.warnings:
        print("\nWarnings")
        for warning in dict.fromkeys(report.warnings):
            print(f"  [warning] {warning}")
    print("\nSummary")
    print(
        f"  left total={report.left.total}, right total={report.right.total}, "
        f"left crossing={report.left.page_crossing}, right crossing={report.right.page_crossing}"
    )
    print(f"  section pair deltas: {report.section_pair_deltas}")
    print(f"  left density: {report.left.density_per_kb}")
    print(f"  right density: {report.right.density_per_kb}")
    if report.missing_in_right:
        print("\nMissing in right")
        for entry in report.missing_in_right:
            print(f"  {entry.owner_type}:{entry.field}->{entry.target_type} crossing={entry.page_crossing}")
    if report.extra_in_right:
        print("\nExtra in right")
        for entry in report.extra_in_right:
            print(f"  {entry.owner_type}:{entry.field}->{entry.target_type} crossing={entry.page_crossing}")
    if report.ordering_differences:
        print("\nOrdering differences")
        for item in report.ordering_differences[:40]:
            print(f"  {item}")
        if len(report.ordering_differences) > 40:
            print(f"  ... {len(report.ordering_differences) - 40} more")


def page_domain_report(path: Path) -> PageDomainReport:
    report = generated_report_from_manifest(path)
    entries: list[PageDomainEntry] = []
    warnings: list[str] = []
    if report:
        pointer_counts: dict[int, int] = {}
        for item in report.objects:
            if item.pointer:
                pointer_counts[item.pointer] = pointer_counts.get(item.pointer, 0) + 1
        duplicate_pointers = [f"0x{pointer:016X}" for pointer, count in pointer_counts.items() if count > 1]
        if duplicate_pointers:
            warnings.append(f"duplicate generated object pointers detected: {', '.join(duplicate_pointers)}")
        for item in report.objects:
            intended = object_domain_for_type(item.type)
            entries.append(
                PageDomainEntry(
                    name=item.name,
                    type=item.type,
                    intended_domain=intended,
                    actual_domain=item.section,
                    offset=item.offset,
                    size=item.size,
                    alignment=alignment_for_offset(item.offset),
                    confidence="HIGH_CONFIDENCE" if intended == item.section else "CONTRADICTED",
                    note="from generated writer manifest",
                )
            )
    else:
        inspection = inspect_file(path, max_entries=100_000, string_limit=0, hex_window_size=0)
        if not inspection.ydr or not inspection.ydr.resource_map:
            raise ParseError(f"{path} does not expose a resource map for page-domain inference")
        for node in inspection.ydr.resource_map.nodes:
            intended = object_domain_for_type(node.type)
            entries.append(
                PageDomainEntry(
                    name=node.label,
                    type=node.type,
                    intended_domain=intended,
                    actual_domain=node.section,
                    offset=node.payload_offset,
                    size=node.length,
                    alignment=alignment_for_offset(node.payload_offset),
                    confidence="INFERRED" if intended == node.section else "UNKNOWN",
                    note="from inferred pointer graph; native page-domain semantics unconfirmed",
                )
            )
        warnings.append("page domains inferred from resource map; native allocator intent is not confirmed")
    return PageDomainReport(path=str(path.resolve()), entries=entries, warnings=warnings)


def print_page_domain_report(report: PageDomainReport) -> None:
    print(f"Page domain report: {report.path}")
    for warning in report.warnings:
        print(f"  [warning] {warning}")
    for entry in report.entries:
        print(
            f"  {entry.type:22} {entry.name:32} -> intended={entry.intended_domain}, "
            f"actual={entry.actual_domain}, offset={entry.offset}, size={entry.size}, "
            f"align={entry.alignment}, confidence={entry.confidence}"
        )


def max_object_end(objects: list[dict[str, Any]], section: str) -> int:
    ends = [
        int(item.get("offset", 0)) + int(item.get("size", 0))
        for item in objects
        if item.get("section") == section
    ]
    return max(ends, default=0)


def count_manifest_crossings(objects: list[dict[str, Any]], fixups: list[dict[str, Any]]) -> int:
    by_name = {item.get("name"): item for item in objects}
    count = 0
    for fixup in fixups:
        owner = by_name.get(fixup.get("owner"))
        target = by_name.get(fixup.get("target"))
        if owner and target and owner.get("section") != target.get("section"):
            count += 1
    return count


def manifest_variant_metrics(item: dict[str, Any]) -> dict[str, Any]:
    writer = item["writer"]
    objects = writer.get("objects", [])
    fixups = writer.get("fixups", [])
    vertex_data_size = sum(obj.get("size", 0) for obj in objects if obj.get("type") == "VertexData")
    index_data_size = sum(obj.get("size", 0) for obj in objects if obj.get("type") == "IndexData")
    texture_payload_size = sum(obj.get("size", 0) for obj in objects if obj.get("type") == "TexturePayload")
    return {
        "vertices": item.get("vertices"),
        "indices": item.get("indices"),
        "triangles": item.get("triangles"),
        "shader_count": item.get("shader_count"),
        "geometry_count": item.get("geometry_count"),
        "texture_payload": item.get("texture_payload"),
        "file_size": Path(item["ydr"]).stat().st_size if Path(item["ydr"]).exists() else None,
        "object_count": len(objects),
        "fixup_count": len(fixups),
        "page_crossing_fixups": count_manifest_crossings(objects, fixups),
        "system_page_size": writer.get("system_size"),
        "graphics_page_size": writer.get("graphics_size"),
        "system_used_end": max_object_end(objects, "system"),
        "graphics_used_end": max_object_end(objects, "graphics"),
        "vertex_data_size": vertex_data_size,
        "index_data_size": index_data_size,
        "texture_payload_size": texture_payload_size,
    }


def classify_field_changes(field: str, values_by_variant: dict[str, Any], baseline: Any) -> str:
    changed = {variant: value for variant, value in values_by_variant.items() if value != baseline}
    if not changed:
        return "remains_constant"
    names = set(changed)
    if names <= {"plus_one_vertex", "plus_one_triangle"} and field in {"vertices", "vertex_data_size", "graphics_used_end"}:
        return "scales_with_vertex_growth"
    if names <= {"plus_one_vertex", "plus_one_triangle", "second_geometry"} and field == "vertex_data_size":
        return "scales_with_vertex_growth_or_geometry_duplication"
    if names <= {"plus_one_triangle"} and field in {"indices", "triangles", "index_data_size"}:
        return "scales_with_index_growth"
    if names <= {"plus_one_triangle", "second_geometry"} and field == "index_data_size":
        return "scales_with_index_growth_or_geometry_duplication"
    if names <= {"uv_modification"}:
        return "changes_with_payload_bytes_only"
    if names <= {"with_texture_payload"} or field == "texture_payload_size":
        return "changes_with_graphics_payload_growth"
    if "second_geometry" in names and field in {"geometry_count", "object_count", "fixup_count", "page_crossing_fixups", "system_used_end"}:
        return "changes_after_topology_expansion"
    if "second_material" in names and field in {"shader_count", "object_count", "fixup_count", "system_used_end", "page_crossing_fixups"}:
        return "changes_after_material_expansion"
    if field == "graphics_used_end":
        return "changes_after_graphics_payload_or_topology_growth"
    return "mixed_or_unknown"


def build_mutation_matrix(manifest_path: Path, baseline_variant: str = "baseline_triangle") -> MutationMatrixReport:
    if manifest_path.is_dir():
        manifest_path = manifest_path / "manifest.json"
    if not manifest_path.is_file():
        raise ParseError(f"manifest not found: {manifest_path}")
    items = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(items, list):
        raise ParseError("manifest must contain a list of variants")
    metrics = {item["name"]: manifest_variant_metrics(item) for item in items}
    if baseline_variant not in metrics:
        raise ParseError(f"baseline variant {baseline_variant!r} not found")
    baseline = metrics[baseline_variant]
    fields = list(baseline)
    cells: list[MutationMatrixCell] = []
    field_classifications: dict[str, str] = {}
    for field in fields:
        values = {variant: data[field] for variant, data in metrics.items()}
        field_classifications[field] = classify_field_changes(field, values, baseline[field])
        for variant, value in values.items():
            cells.append(
                MutationMatrixCell(
                    variant=variant,
                    field=field,
                    baseline=baseline[field],
                    value=value,
                    classification="same" if value == baseline[field] else field_classifications[field],
                )
            )
    warnings: list[str] = []
    if field_classifications.get("file_size") == "remains_constant":
        warnings.append("file/page size remains constant across generated variants due to fixed 8 KB system/graphics allocation")
    return MutationMatrixReport(
        manifest_path=str(manifest_path.resolve()),
        baseline_variant=baseline_variant,
        cells=cells,
        field_classifications=field_classifications,
        warnings=warnings,
    )


def print_mutation_matrix(report: MutationMatrixReport) -> None:
    print(f"Mutation matrix: {report.manifest_path}")
    print(f"Baseline: {report.baseline_variant}")
    for warning in report.warnings:
        print(f"  [warning] {warning}")
    print("\nField classifications")
    for field, classification in report.field_classifications.items():
        print(f"  {field}: {classification}")
    print("\nChanged cells")
    for cell in report.cells:
        if cell.classification == "same":
            continue
        print(
            f"  {cell.variant:22} {cell.field:22} "
            f"baseline={cell.baseline!r} value={cell.value!r} -> {cell.classification}"
        )


def project_generated_paths(root: Path = Path(".")) -> set[Path]:
    generated: set[Path] = set()
    for manifest in root.rglob("manifest.json"):
        try:
            items = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and item.get("ydr"):
                generated.add(Path(item["ydr"]).resolve())
            writer = item.get("writer") if isinstance(item, dict) else None
            if isinstance(writer, dict) and writer.get("output_path"):
                generated.add(Path(writer["output_path"]).resolve())
    for path in root.rglob("*.ydr"):
        if any(part in {"controlled_ydr_variants", "triangle_rage_sample"} for part in path.parts):
            generated.add(path.resolve())
        if path.name in {"p_humanskinmask01x.structured.ydr", "p_humanskinmask01x.metadata.ydr", "sample_drawable_3_models.ydr"}:
            generated.add(path.resolve())
    return generated


def is_probably_project_generated(path: Path, generated_paths: set[Path]) -> bool:
    resolved = path.resolve()
    if "known_good" in {part.lower() for part in resolved.parts}:
        return False
    if resolved in generated_paths:
        return True
    lower_parts = {part.lower() for part in resolved.parts}
    if "binary packer" in str(resolved).lower() and "tests" in lower_parts:
        return True
    if path.name.lower() == "p_humanskinmask01x.ydr" and "humanskinningmask" in str(resolved).lower():
        return True
    return False


def scan_ydr_candidate_paths(roots: list[Path], max_files: int | None = None) -> list[Path]:
    candidates: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        iterator = [root] if root.is_file() else root.rglob("*.ydr")
        for path in iterator:
            if max_files is not None and len(candidates) >= max_files:
                return candidates
            if path.is_file() and path.suffix.lower() == ".ydr":
                candidates.append(path)
    return sorted(set(candidates))


def classify_native_ydr_candidate(path: Path, generated_paths: set[Path]) -> NativeYdrCandidate:
    generated = is_probably_project_generated(path, generated_paths)
    try:
        inspection = inspect_file(path, max_entries=100_000, string_limit=0, hex_window_size=0)
    except Exception as exc:
        return NativeYdrCandidate(
            path=str(path.resolve()),
            file_size=path.stat().st_size if path.exists() else 0,
            format="unreadable",
            resource_type=None,
            header_interpretation=None,
            drawable_models=None,
            generated_by_project=generated,
            suitability="reject",
            reason=f"could not inspect safely: {exc}",
        )
    header_interpretation = None
    if isinstance(inspection.header, Rsc8Header):
        header_interpretation = inspection.header.interpretation
    elif isinstance(inspection.header, Rsc7Header):
        header_interpretation = "rsc7"
    drawable_models = inspection.ydr.drawable_models if inspection.ydr else None
    suitability = "reject"
    reason = "not an inspectable drawable resource"
    if generated:
        reason = "project-generated candidate; useful for generated/generated tests but not native oracle"
    elif inspection.guessed_resource_type != "Drawable":
        reason = f"extension is .ydr but guessed type is {inspection.guessed_resource_type}"
    elif not isinstance(inspection.header, Rsc8Header):
        suitability = "maybe"
        reason = "drawable is not RSC8; useful only if the native tool intentionally emits this wrapper"
    elif header_interpretation == "raw-rsc8":
        suitability = "strong"
        reason = "loose RSC8 drawable not recognized as this project's experimental wrapper"
    elif header_interpretation == "experimental-rsc8-with-rsc7-page-words":
        suitability = "weak"
        reason = "RSC8 drawable uses legacy-compatible words; may be generated by this project or non-native"
    return NativeYdrCandidate(
        path=str(path.resolve()),
        file_size=inspection.file_size,
        format=inspection.format,
        resource_type=inspection.guessed_resource_type,
        header_interpretation=header_interpretation,
        drawable_models=drawable_models,
        generated_by_project=generated,
        suitability=suitability,
        reason=reason,
    )


def find_native_ydr_candidates(roots: list[Path], max_files: int | None = None) -> NativeYdrCandidateReport:
    generated_paths = project_generated_paths(Path("."))
    paths = scan_ydr_candidate_paths(roots, max_files=max_files)
    candidates = [classify_native_ydr_candidate(path, generated_paths) for path in paths]
    best = [item for item in candidates if item.suitability in {"strong", "maybe"} and not item.generated_by_project]
    warnings: list[str] = []
    if not best:
        warnings.append("no confirmed native minimal .ydr candidate found in scanned roots")
    if any(item.generated_by_project for item in candidates):
        warnings.append("project-generated .ydr files were detected and excluded from best native candidates")
    return NativeYdrCandidateReport(
        roots=[str(root.resolve()) for root in roots],
        candidates=candidates,
        best_candidates=best,
        warnings=warnings,
    )


def print_native_ydr_candidate_report(report: NativeYdrCandidateReport) -> None:
    print("Native YDR candidate scan")
    print("Roots")
    for root in report.roots:
        print(f"  {root}")
    if report.warnings:
        print("\nWarnings")
        for warning in report.warnings:
            print(f"  [warning] {warning}")
    print("\nBest candidates")
    if not report.best_candidates:
        print("  <none>")
    for item in report.best_candidates:
        print(f"  {item.suitability}: {item.path}")
        print(f"    format={item.format}, models={item.drawable_models}, reason={item.reason}")
    print("\nAll .ydr files")
    for item in report.candidates:
        generated = " generated-by-project" if item.generated_by_project else ""
        print(f"  {item.suitability}{generated}: {item.path}")
        print(
            f"    size={item.file_size}, format={item.format}, type={item.resource_type}, "
            f"interpretation={item.header_interpretation}, models={item.drawable_models}"
        )
        print(f"    reason={item.reason}")


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts if count)


def classify_region(entropy: float, zero_ratio: float, printable_ratio: float) -> str:
    if entropy >= 7.8 and zero_ratio < 0.02:
        return "high_entropy_transformed_or_compressed"
    if zero_ratio > 0.5:
        return "zero_padding_or_sparse"
    if printable_ratio > 0.6:
        return "text_or_metadata_like"
    return "mixed_unknown"


def build_region_stats(label: str, offset: int, data: bytes) -> ByteRegionStats:
    length = len(data)
    if length == 0:
        return ByteRegionStats(label, offset, 0, 0.0, 0.0, 0.0, 0, "", "empty")
    entropy = byte_entropy(data)
    zero_ratio = data.count(0) / length
    printable_ratio = sum(1 for byte in data if 32 <= byte < 127) / length
    return ByteRegionStats(
        label=label,
        offset=offset,
        length=length,
        entropy=round(entropy, 4),
        zero_ratio=round(zero_ratio, 4),
        printable_ratio=round(printable_ratio, 4),
        unique_byte_count=len(set(data)),
        raw_prefix=compact_hex(data[:64]),
        classification=classify_region(entropy, zero_ratio, printable_ratio),
    )


def zlib_probe(payload: bytes, name: str, wbits: int) -> TransformProbe:
    try:
        output = zlib.decompress(payload, wbits)
        return TransformProbe(name=name, status="ok", output_size=len(output), note=compact_hex(output[:16]))
    except zlib.error as exc:
        return TransformProbe(name=name, status="failed", note=str(exc))


def find_oodle_dll() -> Path | None:
    candidates = [
        Path(r"E:\Red Dead Redemption 2\oo2core_5_win64.dll"),
        Path("oo2core_5_win64.dll"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def oodle_candidate_sizes(payload_size: int, word2: int, word3: int) -> list[int]:
    values: set[int] = set()
    for value in (
        payload_size,
        payload_size * 2,
        payload_size * 3,
        payload_size * 4,
        word2,
        word3,
        word2 + word3,
        word2 & 0xFFFFFFFE,
        word3 & 0xFFFFFFFE,
        (word2 & 0xFFFFFFFE) + (word3 & 0xFFFFFFFE),
        word2 & 0xFFFFFF00,
        word3 & 0xFFFFFF00,
        (word2 & 0xFFFFFF00) + (word3 & 0xFFFFFF00),
        align(word2 + word3, 16),
        align(word2 + word3, 4096),
        align(payload_size, 4096),
    ):
        if 16 <= value <= 16_000_000:
            values.add(value)
    return sorted(values)


def oodle_probe(payload: bytes, word2: int, word3: int) -> list[TransformProbe]:
    dll = find_oodle_dll()
    if dll is None:
        return [TransformProbe(name="oodle", status="not_available", note="oo2core_5_win64.dll not found")]
    try:
        oodle = ctypes.CDLL(str(dll))
        decompress = oodle.OodleLZ_Decompress
        decompress.restype = ctypes.c_int
        decompress.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
    except (OSError, AttributeError) as exc:
        return [TransformProbe(name="oodle", status="failed", note=f"could not load Oodle: {exc}")]
    probes: list[TransformProbe] = []
    source = ctypes.create_string_buffer(payload)
    for output_size in oodle_candidate_sizes(len(payload), word2, word3):
        destination = ctypes.create_string_buffer(output_size)
        result = decompress(
            source,
            len(payload),
            destination,
            output_size,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
            None,
            0,
            0,
        )
        if result <= 16:
            continue
        output = destination.raw[: min(result, output_size)]
        if output[: min(64, len(output))] == payload[1 : 1 + min(64, len(output))]:
            status = "copy_like_rejected"
            note = f"returned {result} bytes but output matches payload shifted by one byte; not credible decoded structure"
        elif byte_entropy(output[: min(len(output), 4096)]) >= 7.8:
            status = "high_entropy_rejected"
            note = f"returned {result} bytes but output remains high entropy"
        else:
            status = "candidate"
            note = compact_hex(output[:32])
        probes.append(TransformProbe(name=f"oodle:{output_size}", status=status, output_size=result, note=note))
        if status == "candidate":
            break
    if not probes:
        probes.append(TransformProbe(name="oodle", status="failed", note=f"{dll} loaded, but candidate sizes did not decode"))
    return probes


def scan_virtual_pointer_hits(payload: bytes, limit: int = 20) -> list[str]:
    hits: list[str] = []
    scan_len = min(len(payload) - 8, 0x40000)
    for offset in range(0, max(0, scan_len), 8):
        value = struct.unpack_from("<Q", payload, offset)[0]
        if 0x50000000 <= value < 0x70000000 and value % 8 == 0:
            hits.append(f"u64@0x{offset:X}=0x{value:016X}")
            if len(hits) >= limit:
                return hits
    return hits


def extract_ascii_hits(data: bytes, limit: int = 20, minimum: int = 5) -> list[str]:
    hits: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
            continue
        if len(current) >= minimum:
            hits.append(current.decode("ascii", errors="replace"))
            if len(hits) >= limit:
                return hits
        current.clear()
    if len(current) >= minimum and len(hits) < limit:
        hits.append(current.decode("ascii", errors="replace"))
    return hits


def native_rsc8_reference_report(path: Path) -> NativeRsc8ReferenceReport:
    inspection = inspect_file(path, max_entries=100_000, string_limit=0, hex_window_size=0)
    if not isinstance(inspection.header, Rsc8Header):
        raise ParseError(f"{path} is not an RSC8 resource")
    header = inspection.header
    data = path.read_bytes()
    payload = data[header.payload_offset :]
    header_fields = [
        NativeReferenceField(0, 4, "magic", hex_range(data, 0, 4), "RSC8", "CONFIRMED", "RSC8 resource wrapper magic"),
        NativeReferenceField(4, 4, "word1", hex_range(data, 4, 4), header.word1_hex, "UNKNOWN", "native RSC8 word1; not legacy version"),
        NativeReferenceField(8, 4, "word2", hex_range(data, 8, 4), header.word2_hex, "UNKNOWN", "native RSC8 word2; page/layout semantics unresolved"),
        NativeReferenceField(12, 4, "word3", hex_range(data, 12, 4), header.word3_hex, "HIGH_CONFIDENCE", "native RSC8 word3 low byte is 0x02 across current loose samples; full meaning unresolved"),
    ]
    legacy_word2 = decode_page_flags(header.word2)
    legacy_word3 = decode_page_flags(header.word3)
    inferred_page_notes = [
        f"legacy probe word2 would decode to {legacy_word2.decoded_size} bytes, which is not accepted as native page evidence",
        f"legacy probe word3 would decode to {legacy_word3.decoded_size} bytes; payload minus this value is {len(payload) - legacy_word3.decoded_size}",
        "payload appears transformed/compressed/encrypted before in-memory pointer graph is available",
    ]
    windows = [
        ("header64", 0, data[:64]),
        ("payload64", 16, payload[:64]),
        ("payload4k", 16, payload[:4096]),
        ("payload_first64k", 16, payload[:65536]),
        ("payload_last64k", 16 + max(0, len(payload) - 65536), payload[-65536:]),
        ("payload_all", 16, payload),
    ]
    probes = [
        zlib_probe(payload, "zlib", zlib.MAX_WBITS),
        zlib_probe(payload, "raw_deflate", -zlib.MAX_WBITS),
        zlib_probe(payload, "gzip_or_zlib", zlib.MAX_WBITS + 32),
    ]
    oodle_probes = oodle_probe(payload, header.word2, header.word3)
    pointer_hits = scan_virtual_pointer_hits(payload)
    string_hits = extract_ascii_hits(payload)
    warnings = [
        "native drawable payload is not decoded into runtime structures yet",
        "do not use generated legacy-compatible RSC8 page words as native evidence",
    ]
    if not pointer_hits:
        warnings.append("no plausible raw 0x50000000/0x60000000 virtual pointers found in early payload scan")
    if all(probe.status == "failed" for probe in probes):
        warnings.append("standard zlib/raw-deflate/gzip probes failed")
    return NativeRsc8ReferenceReport(
        path=str(path.resolve()),
        file_size=inspection.file_size,
        resource_type=inspection.guessed_resource_type or "unknown",
        header_fields=header_fields,
        region_stats=[build_region_stats(label, offset, blob) for label, offset, blob in windows],
        transform_probes=probes,
        oodle_probes=oodle_probes,
        pointer_scan_hits=pointer_hits,
        string_hits=string_hits,
        inferred_page_notes=inferred_page_notes,
        structural_status="TRANSFORMED_PAYLOAD_NO_RUNTIME_GRAPH_YET",
        warnings=warnings,
    )


def print_native_rsc8_reference_report(report: NativeRsc8ReferenceReport) -> None:
    print("Native RSC8 reference report")
    print(f"Path: {report.path}")
    print(f"File size: {report.file_size}")
    print(f"Resource type: {report.resource_type}")
    print(f"Structural status: {report.structural_status}")
    if report.warnings:
        print("\nWarnings")
        for warning in report.warnings:
            print(f"  [warning] {warning}")
    print("\nHeader fields")
    for field in report.header_fields:
        print(f"  0x{field.offset:02X}-0x{field.offset + field.length - 1:02X} {field.field}: {field.value} {field.confidence}")
        print(f"    raw={field.raw_hex}")
        print(f"    note={field.note}")
    print("\nRegion stats")
    for stat in report.region_stats:
        print(
            f"  {stat.label}: offset=0x{stat.offset:X}, length={stat.length}, "
            f"entropy={stat.entropy}, zero={stat.zero_ratio}, printable={stat.printable_ratio}, "
            f"unique={stat.unique_byte_count}, class={stat.classification}"
        )
        print(f"    prefix={stat.raw_prefix}")
    print("\nTransform probes")
    for probe in report.transform_probes:
        print(f"  {probe.name}: {probe.status}, output_size={probe.output_size}, note={probe.note}")
    print("\nOodle probes")
    for probe in report.oodle_probes:
        print(f"  {probe.name}: {probe.status}, output_size={probe.output_size}, note={probe.note}")
    print("\nPointer scan")
    if report.pointer_scan_hits:
        for hit in report.pointer_scan_hits:
            print(f"  {hit}")
    else:
        print("  <none>")
    print("\nASCII/string scan")
    if report.string_hits:
        for hit in report.string_hits:
            print(f"  {hit}")
    else:
        print("  <none>")
    print("\nPage notes")
    for note in report.inferred_page_notes:
        print(f"  {note}")


def backup_path(path: Path) -> Path:
    suffix = path.suffix
    index = 1
    while True:
        candidate = path.with_suffix(f"{suffix}.bak{index}")
        if not candidate.exists():
            return candidate
        index += 1


def ensure_lml_streaming_entries(install_xml: Path, streaming_files: list[str]) -> tuple[list[str], Path | None]:
    if not install_xml.exists():
        root = ElementTree.Element("EasyInstall")
        ElementTree.SubElement(root, "Name").text = "Human Skinning Mask"
        ElementTree.SubElement(root, "Author").text = "Local"
        ElementTree.SubElement(root, "Version").text = "0.3-binary-packer-stage"
        addons = ElementTree.SubElement(root, "Addons")
        addon = ElementTree.SubElement(addons, "Addon")
        tree = ElementTree.ElementTree(root)
        backup = None
    else:
        backup = backup_path(install_xml)
        shutil.copy2(install_xml, backup)
        tree = ElementTree.parse(install_xml)
        root = tree.getroot()
        addons = root.find("./Addons")
        if addons is None:
            addons = ElementTree.SubElement(root, "Addons")
        addon = addons.find("./Addon")
        if addon is None:
            addon = ElementTree.SubElement(addons, "Addon")
    existing = [item.text.strip() for item in addon.findall("./StreamingFile") if item.text and item.text.strip()]
    for streaming_file in streaming_files:
        if streaming_file not in existing:
            ElementTree.SubElement(addon, "StreamingFile").text = streaming_file
            existing.append(streaming_file)
    install_xml.parent.mkdir(parents=True, exist_ok=True)
    tree.write(install_xml, encoding="utf-8", xml_declaration=True)
    return existing, backup


def stage_lml_mask(
    xml_path: Path,
    package_path: Path,
    update_install_xml: bool = True,
    version: int = 165,
    endian: str = "little",
    resource_format: str = "rsc8",
) -> LmlStageReport:
    drawable = parse_drawable_xml(xml_path)
    stream_path = package_path / "stream"
    stream_path.mkdir(parents=True, exist_ok=True)
    ydr_path = stream_path / f"{drawable.name}.ydr"
    report = write_ydr_xml_structures(xml_path, ydr_path, version=version, endian=endian, resource_format=resource_format)
    install_xml = package_path / "install.xml"
    streaming_files = [f"stream/{drawable.name}.ydr"]
    install_entries: list[str] = []
    backup: Path | None = None
    if update_install_xml:
        install_entries, backup = ensure_lml_streaming_entries(install_xml, streaming_files)
    else:
        install_entries = streaming_files

    issues: list[str] = []
    warnings: list[str] = list(report.warnings)
    lml_visible = ydr_path.exists() and (not update_install_xml or all(item in install_entries for item in streaming_files))
    native_rdr2_valid = False
    try:
        inspection = inspect_file(ydr_path, max_entries=100_000, string_limit=0)
        if inspection.format != "RSC8 resource":
            issues.append(
                f"staged .ydr is {inspection.format}; local streamed RDR2 resources observed so far use RSC8"
            )
        if isinstance(inspection.header, Rsc8Header) and inspection.header.interpretation != "raw-rsc8":
            warnings.append(f"staged .ydr uses {inspection.header.interpretation}")
        if inspection.ydr is None:
            issues.append("staged .ydr does not parse as a confirmed native RDR2 YDR")
    except ParseError as exc:
        issues.append(f"staged .ydr inspection failed: {exc}")
    ytyp_path = stream_path / f"{drawable.name}.ytyp"
    if not ytyp_path.exists():
        warnings.append(
            f"no native {ytyp_path.name} was staged; LML may need a matching archetype/type file for new drawable streaming"
        )
    warnings.append(
        "staged file is experimental: shader binding, native texture encoding, and RDR2 RSC8/resource layout are not confirmed"
    )
    return LmlStageReport(
        package_path=str(package_path.resolve()),
        stream_path=str(stream_path.resolve()),
        ydr_path=str(ydr_path.resolve()),
        install_xml_path=str(install_xml.resolve()),
        install_xml_backup=None if backup is None else str(backup.resolve()),
        streaming_entries=install_entries,
        lml_visible=lml_visible,
        native_rdr2_valid=native_rdr2_valid,
        issues=issues,
        warnings=warnings,
    )


def print_lml_stage_report(report: LmlStageReport) -> None:
    print("LML staging report")
    print(f"Package: {report.package_path}")
    print(f"Stream: {report.stream_path}")
    print(f"YDR: {report.ydr_path}")
    print(f"install.xml: {report.install_xml_path}")
    if report.install_xml_backup:
        print(f"install.xml backup: {report.install_xml_backup}")
    print(f"LML visible: {report.lml_visible}")
    print(f"Native RDR2 valid: {report.native_rdr2_valid}")
    if report.streaming_entries:
        print("Streaming entries:")
        for entry in report.streaming_entries:
            print(f"  {entry}")
    if report.issues:
        print("\nIssues")
        for issue in report.issues:
            print(f"  [issue] {issue}")
    if report.warnings:
        print("\nWarnings")
        for warning in report.warnings:
            print(f"  [warning] {warning}")


def extract_first_raw_rsc7_resource_from_rpf8(path: Path, output_path: Path) -> Path | None:
    hits = find_valid_rsc7_resources(path, max_hits=1)
    if not hits:
        return None
    hit = hits[0]
    with path.open("rb") as handle:
        handle.seek(hit.offset)
        header_data = handle.read(16)
    if len(header_data) < 16:
        return None
    view = BinaryView(header_data)
    header = parse_rsc7(view)
    total_size = 16 + header.decoded_total_size
    with path.open("rb") as handle:
        handle.seek(hit.offset)
        payload = handle.read(total_size)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(payload)
    return output_path


def try_extract_known_good_ydr_from_rpf8(
    game_root: Path,
    output_path: Path,
    max_files: int | None = None,
) -> tuple[Path | None, list[str]]:
    messages: list[str] = []
    for index, rpf_path in enumerate(iter_rpf8_files(game_root)):
        if max_files is not None and index >= max_files:
            messages.append(f"Stopped after --max-files={max_files}")
            break
        with rpf_path.open("rb") as handle:
            prefix = handle.read(16)
        if not prefix.startswith(RPF8_MAGIC):
            continue
        messages.append(f"scanning {rpf_path}")
        extracted = extract_first_raw_rsc7_resource_from_rpf8(rpf_path, output_path)
        if extracted is not None:
            messages.append(f"extracted raw RSC7 resource from {rpf_path}")
            return extracted, messages
    messages.append(
        "No raw RSC7 resources were found in the RPF8 archives. The installed RDR2 archives appear to keep resource entries behind the RPF8 TOC/compression/encryption layer, so a known-good .ydr cannot be extracted by signature scanning."
    )
    return None, messages


def read_c_string(buf: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(buf):
        return f"<invalid-name-offset:{offset}>"
    end = buf.find(b"\x00", offset, min(len(buf), offset + limit))
    if end == -1:
        end = min(len(buf), offset + limit)
    raw = buf[offset:end]
    return raw.decode("utf-8", errors="replace")


def find_binary_signatures(
    path: Path,
    signatures: tuple[bytes, ...],
    max_hits: int = 100,
    chunk_size: int = 8 * 1024 * 1024,
) -> list[SignatureHit]:
    hits: list[SignatureHit] = []
    max_sig_len = max(len(signature) for signature in signatures)
    overlap = b""
    base_offset = 0
    with path.open("rb") as handle:
        while len(hits) < max_hits:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            data = overlap + chunk
            data_base = base_offset - len(overlap)
            for signature in signatures:
                start = 0
                while len(hits) < max_hits:
                    index = data.find(signature, start)
                    if index < 0:
                        break
                    absolute = data_base + index
                    if absolute >= 0:
                        hits.append(SignatureHit(signature.decode("ascii", errors="replace"), absolute))
                    start = index + 1
            overlap = data[-(max_sig_len - 1) :] if max_sig_len > 1 else b""
            base_offset += len(chunk)
    hits.sort(key=lambda item: item.offset)
    return hits


def find_valid_rsc7_resources(path: Path, max_hits: int = 20) -> list[SignatureHit]:
    valid_hits: list[SignatureHit] = []
    file_size = path.stat().st_size
    for hit in find_binary_signatures(path, (RSC7_MAGIC,), max_hits=500):
        if len(valid_hits) >= max_hits:
            break
        with path.open("rb") as handle:
            handle.seek(hit.offset)
            header_data = handle.read(16)
        if len(header_data) < 16:
            continue
        try:
            header = parse_rsc7(BinaryView(header_data))
        except ParseError:
            continue
        if not (0 < header.version <= 255):
            continue
        decoded_size = header.decoded_total_size
        remaining = file_size - hit.offset - 16
        if decoded_size <= 0 or decoded_size > remaining:
            continue
        if decoded_size > 512 * 1024 * 1024:
            continue
        valid_hits.append(hit)
    return valid_hits


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def ratio(count: int, total: int) -> float:
    return 0.0 if total == 0 else count / total


def decompression_status(data: bytes, window_bits: int) -> str:
    try:
        output = zlib.decompress(data, window_bits)
    except zlib.error as exc:
        return f"failed: {exc.args[0] if exc.args else 'zlib error'}"
    return f"ok: {len(output)} bytes"


def plausible_rpf8_entry_ratio(data: bytes, entry_size: int, toc_size: int, file_size: int) -> float:
    if not data or entry_size <= 0:
        return 0.0
    count = min(len(data) // entry_size, 512)
    if count == 0:
        return 0.0
    plausible = 0
    for index in range(count):
        entry = data[index * entry_size : (index + 1) * entry_size]
        if len(entry) < 16:
            continue
        name_offset = int.from_bytes(entry[0:4], "little")
        second = int.from_bytes(entry[4:8], "little")
        third = int.from_bytes(entry[8:12], "little")
        fourth = int.from_bytes(entry[12:16], "little")
        name_ok = name_offset < toc_size
        directory_like = name_ok and second <= 0x7FFFFFFF and third < 2_000_000 and fourth < 2_000_000
        file_like = name_ok and second <= file_size and (third & 0x00FFFFFF) * 512 <= file_size
        if directory_like or file_like:
            plausible += 1
    return plausible / count


def analyze_rpf8_toc_regions(path: Path, entry_count: int, toc_size: int) -> list[TocRegionAnalysis]:
    file_size = path.stat().st_size
    regions: list[TocRegionAnalysis] = []
    candidate_offsets = []
    for offset in (16, 2048):
        if offset not in candidate_offsets:
            candidate_offsets.append(offset)
    for offset in candidate_offsets:
        if offset >= file_size:
            continue
        size = min(max(toc_size, entry_count * 16, 2048), 256 * 1024, file_size - offset)
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(size)
        printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (0, 9, 10, 13))
        zero = data.count(0)
        regions.append(
            TocRegionAnalysis(
                offset=offset,
                size=len(data),
                entropy=round(shannon_entropy(data), 4),
                printable_ratio=round(ratio(printable, len(data)), 4),
                zero_ratio=round(ratio(zero, len(data)), 4),
                zlib_status=decompression_status(data, zlib.MAX_WBITS),
                raw_deflate_status=decompression_status(data, -zlib.MAX_WBITS),
                entry16_plausible_ratio=round(plausible_rpf8_entry_ratio(data, 16, toc_size, file_size), 4),
                entry20_plausible_ratio=round(plausible_rpf8_entry_ratio(data, 20, toc_size, file_size), 4),
            )
        )
    return regions


def infer_rpf8_toc_transform(regions: list[TocRegionAnalysis]) -> tuple[str, list[str]]:
    if not regions:
        return "unknown", ["no TOC regions were available for analysis"]
    evidence: list[str] = []
    high_entropy = all(region.entropy >= 7.85 for region in regions)
    no_plain_entries = all(
        region.entry16_plausible_ratio < 0.05 and region.entry20_plausible_ratio < 0.05
        for region in regions
    )
    no_standard_inflate = all(
        region.zlib_status.startswith("failed") and region.raw_deflate_status.startswith("failed")
        for region in regions
    )
    if high_entropy:
        evidence.append("candidate TOC windows have near-random entropy")
    if no_plain_entries:
        evidence.append("16-byte and 20-byte plaintext RPF entry heuristics do not match")
    if no_standard_inflate:
        evidence.append("standard zlib and raw-deflate probes fail")
    if high_entropy and no_plain_entries and no_standard_inflate:
        evidence.append("public RDR2/RPF8 notes describe an RDR2 encryption layer; RPFTool WIP discussion specifically references AES key extraction")
        return "encrypted RPF8 TOC, likely AES-family stream/block transform before entry decoding", evidence
    if no_standard_inflate and not no_plain_entries:
        return "possibly plaintext or custom-packed TOC; entry layout needs decoding", evidence
    if not no_standard_inflate:
        return "compressed TOC candidate; inspect successful decompression output", evidence
    return "unknown RPF8 TOC transform", evidence


def parse_rpf8_header_bytes(data: bytes, path: Path | None = None, scan_signatures: bool = False) -> Rpf8Header:
    if len(data) < 16:
        raise ParseError("RPF8 header is shorter than 16 bytes")
    if data[:4] != RPF8_MAGIC:
        raise ParseError("missing RPF8 magic")
    flags_raw = struct.unpack_from("<I", data, 12)[0]
    header = Rpf8Header(
        magic="8FPR",
        entry_count_guess=struct.unpack_from("<I", data, 4)[0],
        toc_size_guess=struct.unpack_from("<I", data, 8)[0],
        flags_raw_hex=f"0x{flags_raw:08X}",
        flags_low=flags_raw & 0xFFFF,
        flags_high=(flags_raw >> 16) & 0xFFFF,
    )
    if path is not None and scan_signatures:
        nested = find_binary_signatures(path, (RPF8_MAGIC,), max_hits=100)
        header.nested_rpf8_offsets = [hit.offset for hit in nested if hit.offset != 0]
        header.resource_signature_hits = find_valid_rsc7_resources(path, max_hits=20)
        header.toc_regions = analyze_rpf8_toc_regions(path, header.entry_count_guess, header.toc_size_guess)
        header.toc_transform_guess, header.toc_transform_evidence = infer_rpf8_toc_transform(header.toc_regions)
    return header


def parse_rpf7(view: BinaryView, max_entries: int, ctx: ParseContext | None = None) -> Rpf7Header:
    if ctx:
        ctx.add_trace("rpf7.header", "reading RPF7 header", offset=0, length=16)
        ctx.add_hex_window(view, 0, "RPF7 header")
    view.require(0, 16, "RPF7 header")
    magic = view.bytes(0, 4)
    if magic != RPF7_MAGIC:
        raise ParseError("missing RPF7 magic")

    entry_count = view.u32(4)
    names_length = view.u32(8)
    encryption_value = view.u32(12)
    encryption = RPF_ENCRYPTION.get(encryption_value, "UNKNOWN")

    if entry_count > max_entries:
        raise ParseError(f"entry_count {entry_count} exceeds max_entries {max_entries}")

    toc_offset = 16
    entries_size = entry_count * 16
    toc_size = entries_size + names_length
    view.require(toc_offset, toc_size, "RPF7 table of contents")
    if ctx:
        ctx.add_trace(
            "rpf7.toc",
            f"entries={entry_count}, names_length={names_length}, encryption={encryption}",
            offset=toc_offset,
            length=toc_size,
        )
        ctx.add_hex_window(view, toc_offset, "RPF7 table of contents")

    header = Rpf7Header(
        magic=magic.decode("ascii"),
        entry_count=entry_count,
        names_length=names_length,
        encryption_value_hex=f"0x{encryption_value:08X}",
        encryption=encryption,
        toc_offset=toc_offset,
        toc_size=toc_size,
    )

    if encryption not in {"NONE", "OPEN"}:
        return header

    names = view.bytes(toc_offset + entries_size, names_length)
    for index in range(entry_count):
        offset = toc_offset + index * 16
        discriminator = view.u32(offset + 4)
        name_offset = view.u16(offset)
        name = read_c_string(names, name_offset)
        if ctx:
            ctx.add_trace("rpf7.entry", f"entry[{index}] discriminator=0x{discriminator:08X} name={name}", offset, 16)

        if discriminator == 0x7FFFFF00:
            header.entries.append(
                RpfEntry(
                    index=index,
                    kind="directory",
                    name=name,
                    name_offset=view.u32(offset),
                    first_child_index=view.u32(offset + 8),
                    child_count=view.u32(offset + 12),
                )
            )
            continue

        size = view.u24(offset + 2)
        file_offset_raw = view.u24(offset + 5)
        file_offset = file_offset_raw & 0x7FFFFF

        if discriminator & 0x80000000:
            system_flags = decode_page_flags(view.u32(offset + 8))
            graphics_flags = decode_page_flags(view.u32(offset + 12))
            header.entries.append(
                RpfEntry(
                    index=index,
                    kind="resource",
                    name=name,
                    name_offset=name_offset,
                    size=size,
                    offset=file_offset,
                    file_offset_bytes=file_offset * 512,
                    system_flags=system_flags,
                    graphics_flags=graphics_flags,
                )
            )
            continue

        file_size = view.u32(offset + 8)
        encryption_type = view.u32(offset + 12)
        header.entries.append(
            RpfEntry(
                index=index,
                kind="binary",
                name=name,
                name_offset=name_offset,
                size=size,
                offset=file_offset,
                file_offset_bytes=file_offset * 512,
                system_flags=None,
                graphics_flags=None,
                child_count=file_size,
            )
        )
        if encryption_type not in (0, 1):
            header.entries[-1].kind = "binary?"

    return header


def extract_ascii_strings(data: bytes, minimum: int, limit: int) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= minimum:
            strings.append(current.decode("ascii", errors="replace"))
            if len(strings) >= limit:
                return strings
        current.clear()
    if len(current) >= minimum and len(strings) < limit:
        strings.append(current.decode("ascii", errors="replace"))
    return strings


def inspect_file(
    path: Path,
    max_entries: int,
    string_limit: int,
    trace: bool = False,
    debug: bool = False,
    hex_window_size: int = 64,
) -> Inspection:
    ext = path.suffix.lower()
    ctx = ParseContext(trace_enabled=trace, debug=debug, hex_window_size=hex_window_size)
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        prefix = handle.read(256)
    result = Inspection(
        path=str(path.resolve()),
        file_name=path.name,
        file_size=file_size,
        extension=ext,
        guessed_resource_type=RESOURCE_EXTENSIONS.get(ext),
        format="unknown",
        header=None,
    )

    if prefix.startswith(RPF8_MAGIC):
        view = BinaryView(prefix)
        result.format = "RPF8 archive"
        result.header = parse_rpf8_header_bytes(prefix)
        if ctx:
            ctx.add_trace("rpf8.header", "detected RDR2 RPF8 archive signature", offset=0, length=16)
            ctx.add_hex_window(view, 0, "RPF8 header")
        result.issues.append(
            Issue(
                "info",
                "RPF8 archive detected. Header scanning is implemented, but encrypted/compressed RDR2 RPF8 TOC extraction is not implemented.",
            )
        )
        result.trace = ctx.trace
        result.hex_windows = ctx.hex_windows
        return result

    data = path.read_bytes()
    view = BinaryView(data)

    try:
        if data.startswith(RSC7_MAGIC):
            result.format = "RSC7 resource"
            result.header = parse_rsc7(view, ctx=ctx)
            if ext == ".ydr":
                try:
                    result.ydr = parse_ydr_info(data, result.header, ctx=ctx)
                except ParseError as exc:
                    result.issues.append(Issue("warning", f"YDR metadata was not parsed: {exc}"))
                    ctx.add_hex_window(view, 16, "YDR parse warning context")
        elif data.startswith(RPF7_MAGIC):
            result.format = "RPF7 archive"
            result.header = parse_rpf7(view, max_entries=max_entries, ctx=ctx)
            if isinstance(result.header, Rpf7Header) and result.header.encryption not in {"NONE", "OPEN"}:
                result.issues.append(
                    Issue(
                        "info",
                        f"TOC uses {result.header.encryption} encryption; entry parsing was skipped.",
                    )
                )
        elif data.startswith(RSC8_MAGIC):
            result.format = "RSC8 resource"
            result.header = parse_rsc8(view, ctx=ctx)
            if isinstance(result.header, Rsc8Header) and result.header.interpretation == "raw-rsc8":
                result.issues.append(
                    Issue(
                        "info",
                        "RSC8 resource detected with native/raw page words; native RDR2 page-size decoding is not fully confirmed.",
                    )
                )
            elif ext == ".ydr":
                try:
                    result.ydr = parse_ydr_info(data, result.header, ctx=ctx)
                except ParseError as exc:
                    result.issues.append(Issue("warning", f"YDR metadata was not parsed: {exc}"))
                    ctx.add_hex_window(view, 16, "YDR parse warning context")
        else:
            result.issues.append(Issue("warning", "No RSC7, RSC8, RPF7, or RPF8 magic found at offset 0."))
            ctx.add_hex_window(view, 0, "unknown file header")
    except ParseError as exc:
        result.issues.append(Issue("error", str(exc)))
        ctx.add_hex_window(view, 0, "parse error context")

    if string_limit > 0:
        result.strings = extract_ascii_strings(data, minimum=5, limit=string_limit)
    result.trace = ctx.trace
    result.hex_windows = ctx.hex_windows
    return result


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    return value


def print_resource_map(resource_map: ResourceMap) -> None:
    print("\nResource map")
    node_by_id = {node.id: node for node in resource_map.nodes}
    children: dict[str, list[ResourceMapEdge]] = {}
    for edge in resource_map.edges:
        children.setdefault(edge.source, []).append(edge)

    def node_text(node: ResourceMapNode) -> str:
        pointer_suffix = f" ({node.pointer})" if node.pointer != "0x0000000000000000" else ""
        return f"{node.label}{pointer_suffix}"

    def walk_edges(node_id: str, prefix: str = "", seen: set[str] | None = None) -> None:
        if node_id in seen:
            print(f"{prefix}  <cycle>")
            return
        seen.add(node_id)
        edges = children.get(node_id, [])
        for index, edge in enumerate(edges):
            branch = "\\-- " if index == len(edges) - 1 else "|-- "
            child_prefix = prefix + ("    " if index == len(edges) - 1 else "|   ")
            target = node_by_id.get(edge.target)
            if target is None:
                print(f"{prefix}{branch}{edge.field}: {edge.status} {edge.pointer}")
                continue
            print(f"{prefix}{branch}{edge.field} -> {node_text(target)}")
            walk_edges(target.id, child_prefix, set(seen))

    root_node = node_by_id.get(resource_map.root)
    if root_node is not None:
        print(node_text(root_node))
        walk_edges(resource_map.root, seen=set())

    invalid = [item for item in resource_map.boundary_validations if item.status == "invalid"]
    nulls = [item for item in resource_map.boundary_validations if item.status == "null"]
    print("\nResource boundary validation")
    valid_count = sum(1 for item in resource_map.boundary_validations if item.status == "valid")
    print(f"  valid={valid_count}, null={len(nulls)}, invalid={len(invalid)}")
    for item in invalid:
        print(f"  [invalid] {item.label}: {item.pointer} - {item.message}")


def print_text(inspection: Inspection, show_resource_map: bool = False) -> None:
    print(f"File: {inspection.path}")
    print(f"Size: {inspection.file_size} bytes")
    print(f"Format: {inspection.format}")
    if inspection.guessed_resource_type:
        print(f"Extension type: {inspection.guessed_resource_type}")

    if isinstance(inspection.header, Rsc7Header):
        h = inspection.header
        print("\nRSC7 header")
        print(f"  Magic: 0x{int.from_bytes(RSC7_MAGIC, 'little'):08X}")
        print(f"  Version: {h.version}")
        if inspection.ydr:
            print(f"  Drawable Models: {inspection.ydr.drawable_models}")
        print(f"  Payload: offset={h.payload_offset}, size={h.payload_size}")
        print(f"  Decoded resource size: {h.decoded_total_size}")
        for label, flags in (("System", h.system_flags), ("Graphics", h.graphics_flags)):
            print(
                f"  {label} flags: {flags.raw_hex}, version={flags.version_nibble}, "
                f"base={flags.base_size}, units={flags.page_units}, size={flags.decoded_size}"
            )
        if inspection.ydr:
            ydr = inspection.ydr
            print(
                "  Drawable model LODs: "
                f"high={ydr.drawable_models_high}, medium={ydr.drawable_models_medium}, "
                f"low={ydr.drawable_models_low}, very_low={ydr.drawable_models_very_low}"
            )
            print(f"  Payload encoding: {ydr.payload_encoding}")
            for model_list in ydr.model_lists:
                if model_list.pointer == 0:
                    continue
                duplicate = ", duplicate" if model_list.is_duplicate_pointer else ""
                payload_offset = (
                    "<unresolved>" if model_list.payload_offset is None else f"0x{model_list.payload_offset:X}"
                )
                print(
                    f"  DrawableModels {model_list.lod}: pointer={model_list.pointer_hex}, "
                    f"payload_offset={payload_offset}, count={model_list.count}, "
                    f"capacity={model_list.capacity}{duplicate}"
                )
            if show_resource_map and ydr.resource_map:
                print_resource_map(ydr.resource_map)

    if isinstance(inspection.header, Rsc8Header):
        h = inspection.header
        print("\nRSC8 header")
        print(f"  Magic: 0x{int.from_bytes(RSC8_MAGIC, 'little'):08X}")
        print(f"  Word1: {h.word1_hex}")
        print(f"  Word2: {h.word2_hex}")
        print(f"  Word3: {h.word3_hex}")
        print(f"  Interpretation: {h.interpretation}")
        if h.legacy_version is not None:
            print(f"  Legacy-compatible version word: {h.legacy_version}")
        print(f"  Payload: offset={h.payload_offset}, size={h.payload_size}")
        if h.decoded_total_size is not None:
            print(f"  Decoded resource size: {h.decoded_total_size}")
        if h.system_flags and h.graphics_flags:
            for label, flags in (("System", h.system_flags), ("Graphics", h.graphics_flags)):
                print(
                    f"  {label} flags: {flags.raw_hex}, version={flags.version_nibble}, "
                    f"base={flags.base_size}, units={flags.page_units}, size={flags.decoded_size}"
                )
        if inspection.ydr:
            print(f"  Drawable Models: {inspection.ydr.drawable_models}")
            ydr = inspection.ydr
            print(
                "  Drawable model LODs: "
                f"high={ydr.drawable_models_high}, medium={ydr.drawable_models_medium}, "
                f"low={ydr.drawable_models_low}, very_low={ydr.drawable_models_very_low}"
            )
            print(f"  Payload encoding: {ydr.payload_encoding}")
            if show_resource_map and ydr.resource_map:
                print_resource_map(ydr.resource_map)

    if isinstance(inspection.header, Rpf7Header):
        h = inspection.header
        print("\nRPF7 header")
        print(f"  Entries: {h.entry_count}")
        print(f"  Names length: {h.names_length}")
        print(f"  Encryption: {h.encryption} ({h.encryption_value_hex})")
        print(f"  TOC: offset={h.toc_offset}, size={h.toc_size}")
        if h.entries:
            print("\nEntries")
            for entry in h.entries:
                name = entry.name or "<root>"
                print(f"  [{entry.index:04}] {entry.kind:9} {name}")
                if entry.kind == "resource":
                    print(
                        f"       packed_size={entry.size}, file_offset={entry.file_offset_bytes}, "
                        f"system={entry.system_flags.raw_hex}/{entry.system_flags.decoded_size}, "
                        f"graphics={entry.graphics_flags.raw_hex}/{entry.graphics_flags.decoded_size}"
                    )
                elif entry.kind == "binary":
                    print(
                        f"       packed_size={entry.size}, unpacked_size={entry.child_count}, "
                        f"file_offset={entry.file_offset_bytes}"
                    )
                elif entry.kind == "directory":
                    print(
                        f"       first_child_index={entry.first_child_index}, child_count={entry.child_count}"
                    )

    if isinstance(inspection.header, Rpf8Header):
        h = inspection.header
        print("\nRPF8 header")
        print(f"  Entries guess: {h.entry_count_guess}")
        print(f"  TOC size guess: {h.toc_size_guess}")
        print(f"  Flags: {h.flags_raw_hex}, low=0x{h.flags_low:04X}, high=0x{h.flags_high:04X}")
        if h.toc_transform_guess != "unknown":
            print(f"  TOC transform guess: {h.toc_transform_guess}")
            for item in h.toc_transform_evidence:
                print(f"    evidence: {item}")
        if h.nested_rpf8_offsets:
            print("  Nested RPF8 offsets:")
            for offset in h.nested_rpf8_offsets[:20]:
                print(f"    0x{offset:X}")
        if h.resource_signature_hits:
            print("  Validated raw RSC7 hits:")
            for hit in h.resource_signature_hits[:20]:
                print(f"    {hit.signature} at {hit.offset_hex}")
        if h.toc_regions:
            print("  TOC region analysis:")
            for region in h.toc_regions:
                print(
                    f"    offset={region.offset_hex}, size={region.size}, entropy={region.entropy:.4f}, "
                    f"printable={region.printable_ratio:.4f}, zeros={region.zero_ratio:.4f}"
                )
                print(
                    f"      zlib={region.zlib_status}; raw_deflate={region.raw_deflate_status}; "
                    f"entry16_plausible={region.entry16_plausible_ratio:.4f}; "
                    f"entry20_plausible={region.entry20_plausible_ratio:.4f}"
                )

    if inspection.strings:
        print("\nASCII strings")
        for value in inspection.strings:
            print(f"  {value}")

    if inspection.issues:
        print("\nIssues")
        for issue in inspection.issues:
            print(f"  [{issue.severity}] {issue.message}")

    if inspection.trace:
        print("\nParse trace")
        for event in inspection.trace:
            location = ""
            if event.offset is not None:
                location = f" offset=0x{event.offset:X}"
                if event.length is not None:
                    location += f" length={event.length}"
            print(f"  {event.label}:{location} {event.message}")

    if inspection.hex_windows:
        print("\nHex windows")
        for window in inspection.hex_windows:
            print(f"  {window.label}: offset=0x{window.offset:X}, length={window.length}")
            print(f"    hex   {window.hex}")
            print(f"    ascii {window.ascii}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Safely inspect Rockstar RAGE RSC7 resource and RPF7 archive metadata."
    )
    subparsers = parser.add_subparsers(dest="command")

    inspect_parser = subparsers.add_parser("inspect", help="Inspect an RSC7 resource or RPF7 archive.")
    inspect_parser.add_argument("file", type=Path, help="Path to a known-good Rockstar resource or RPF file.")
    inspect_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    inspect_parser.add_argument("--trace", action="store_true", help="Print structured parse trace events.")
    inspect_parser.add_argument("--debug", action="store_true", help="Print parse trace and hex window context.")
    inspect_parser.add_argument("--resource-map", action="store_true", help="Print pointer resolution graph and boundary validation summary.")
    inspect_parser.add_argument(
        "--hex-window",
        type=int,
        default=64,
        help="Number of bytes to include in each debug hex window.",
    )
    inspect_parser.add_argument(
        "--max-entries",
        type=int,
        default=100_000,
        help="Maximum RPF entries to parse before rejecting the file.",
    )
    inspect_parser.add_argument(
        "--strings",
        type=int,
        default=0,
        metavar="N",
        help="Also print up to N ASCII strings found in the file.",
    )

    fixture_parser = subparsers.add_parser("make-fixture", help="Write a safe sample .ydr fixture.")
    fixture_parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_FIXTURE_PATH,
        help=f"Fixture output path. Default: {DEFAULT_FIXTURE_PATH}",
    )
    fixture_parser.add_argument("--verify", action="store_true", help="Inspect the generated fixture after writing it.")
    fixture_parser.add_argument("--debug", action="store_true", help="Use debug output when verifying.")
    fixture_parser.add_argument("--resource-map", action="store_true", help="Show resource map when verifying.")

    pack_parser = subparsers.add_parser(
        "pack-ydr-xml",
        help="Pack drawable XML into a metadata-only inspectable .ydr skeleton.",
    )
    pack_parser.add_argument("--xml", type=Path, default=DEFAULT_MASK_XML_PATH, help="Input .ydr.xml path.")
    pack_parser.add_argument(
        "--out",
        type=Path,
        default=Path("tests/fixtures/p_humanskinmask01x.metadata.ydr"),
        help="Output .ydr path.",
    )
    pack_parser.add_argument("--version", type=int, default=165, help="RSC7 version to write.")
    pack_parser.add_argument("--verify", action="store_true", help="Inspect the generated .ydr after writing it.")
    pack_parser.add_argument("--debug", action="store_true", help="Use debug output when verifying.")
    pack_parser.add_argument("--resource-map", action="store_true", help="Show resource map when verifying.")

    xml_parser = subparsers.add_parser(
        "summarize-ydr-xml",
        help="Parse drawable XML into typed objects and print a structured summary.",
    )
    xml_parser.add_argument("--xml", type=Path, default=DEFAULT_MASK_XML_PATH, help="Input .ydr.xml path.")
    xml_parser.add_argument("--json", action="store_true", help="Print parsed typed object model as JSON.")

    structure_writer_parser = subparsers.add_parser(
        "write-ydr-xml-structures",
        help="Write fixed-layout binary structures from drawable XML.",
    )
    structure_writer_parser.add_argument("--xml", type=Path, default=DEFAULT_MASK_XML_PATH, help="Input .ydr.xml path.")
    structure_writer_parser.add_argument(
        "--out",
        type=Path,
        default=Path("tests/fixtures/p_humanskinmask01x.structured.ydr"),
        help="Output .ydr path.",
    )
    structure_writer_parser.add_argument("--version", type=int, default=165, help="RSC7 version to write.")
    structure_writer_parser.add_argument(
        "--endian",
        choices=("little", "big"),
        default="little",
        help="Endian behavior for vertex/index stream packing.",
    )
    structure_writer_parser.add_argument(
        "--resource-format",
        choices=("rsc7", "rsc8"),
        default="rsc7",
        help="Resource wrapper to write. RSC8 is experimental until native page words are confirmed.",
    )
    structure_writer_parser.add_argument("--verify", action="store_true", help="Inspect the generated .ydr after writing it.")
    structure_writer_parser.add_argument("--resource-map", action="store_true", help="Show resource map when verifying.")

    compare_parser = subparsers.add_parser(
        "compare-ydr-structures",
        help="Compare confirmed YDR structure fields between a known-good sample and a candidate.",
    )
    compare_parser.add_argument("--known-good", type=Path, required=True, help="Known-good extracted .ydr sample.")
    compare_parser.add_argument("--candidate", type=Path, required=True, help="Generated or modified .ydr to compare.")
    compare_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    compare_parser.add_argument("--only-diffs", action="store_true", help="Only print differing fields in text mode.")
    compare_parser.add_argument(
        "--dump-known-good",
        action="store_true",
        help="Print the known-good structure snapshot before the comparison.",
    )
    compare_parser.add_argument(
        "--dump-candidate",
        action="store_true",
        help="Print the candidate structure snapshot before the comparison.",
    )

    scan_rpf8_parser = subparsers.add_parser(
        "scan-rpf8",
        help="Scan RDR2 RPF8 archives for headers, nested RPF8 containers, and raw resource signatures.",
    )
    scan_rpf8_parser.add_argument("path", type=Path, help="RPF8 file or game directory to scan.")
    scan_rpf8_parser.add_argument("--no-signatures", action="store_true", help="Only parse top-level headers.")
    scan_rpf8_parser.add_argument("--max-files", type=int, default=None, help="Maximum .rpf files to scan under a directory.")
    scan_rpf8_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    extract_rpf8_parser = subparsers.add_parser(
        "extract-rpf8-ydr",
        help="Attempt to extract a raw known-good RSC7 .ydr from local RDR2 RPF8 archives.",
    )
    extract_rpf8_parser.add_argument(
        "--game-root",
        type=Path,
        default=Path("E:/Red Dead Redemption 2"),
        help="Local RDR2 install directory.",
    )
    extract_rpf8_parser.add_argument(
        "--out",
        type=Path,
        default=Path("tests/known_good/extracted_known_good.ydr"),
        help="Output path for an extracted raw RSC7 resource if one is found.",
    )
    extract_rpf8_parser.add_argument(
        "--max-files",
        type=int,
        default=12,
        help="Maximum .rpf files to scan. Default keeps this bounded because full RDR2 scans are very large.",
    )

    decode_rpf8_toc_parser = subparsers.add_parser(
        "decode-rpf8-toc",
        help="Decode a legitimately obtained plaintext/decrypted RPF8 TOC blob into candidate entries.",
    )
    decode_rpf8_toc_parser.add_argument("--toc", type=Path, required=True, help="Plaintext/decrypted TOC blob path.")
    decode_rpf8_toc_parser.add_argument("--entry-count", type=int, required=True, help="Number of TOC entries.")
    decode_rpf8_toc_parser.add_argument("--entry-size", type=int, choices=(16, 20), default=16, help="Entry size in bytes.")
    decode_rpf8_toc_parser.add_argument(
        "--names-offset",
        type=lambda value: int(value, 0),
        default=None,
        help="Offset of the names table inside the TOC blob. Defaults to entry_count * entry_size.",
    )
    decode_rpf8_toc_parser.add_argument("--max-entries", type=int, default=100_000, help="Safety limit for entries.")
    decode_rpf8_toc_parser.add_argument("--limit", type=int, default=100, help="Maximum entries to print in text mode.")
    decode_rpf8_toc_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    stage_lml_parser = subparsers.add_parser(
        "stage-lml-mask",
        help="Stage the generated mask .ydr into the local LML package and update install.xml.",
    )
    stage_lml_parser.add_argument("--xml", type=Path, default=DEFAULT_MASK_XML_PATH, help="Input .ydr.xml path.")
    stage_lml_parser.add_argument(
        "--package",
        type=Path,
        default=DEFAULT_LML_MASK_PACKAGE_PATH,
        help="LML package directory.",
    )
    stage_lml_parser.add_argument("--version", type=int, default=165, help="RSC version for the generated candidate.")
    stage_lml_parser.add_argument(
        "--endian",
        choices=("little", "big"),
        default="little",
        help="Endian behavior for vertex/index stream packing.",
    )
    stage_lml_parser.add_argument(
        "--resource-format",
        choices=("rsc7", "rsc8"),
        default="rsc8",
        help="Resource wrapper to stage. Defaults to experimental RSC8 because local streamed RDR2 resources use RSC8.",
    )
    stage_lml_parser.add_argument("--no-install-update", action="store_true", help="Do not modify install.xml.")
    stage_lml_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    rsc8_corpus_parser = subparsers.add_parser(
        "analyze-rsc8-corpus",
        help="Analyze local loose RSC8 resources to infer header word patterns.",
    )
    rsc8_corpus_parser.add_argument("root", type=Path, help="File or directory to scan for loose RSC8 resources.")
    rsc8_corpus_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    native_tool_parser = subparsers.add_parser(
        "detect-native-ydr-tools",
        help="Detect local legitimate tool paths that could generate a native RDR2 RSC8 .ydr sample.",
    )
    native_tool_parser.add_argument(
        "--root",
        action="append",
        type=Path,
        default=None,
        help="Additional root to scan. Can be repeated. Defaults to common local tool/add-on locations.",
    )
    native_tool_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    header_compare_parser = subparsers.add_parser(
        "compare-resource-headers",
        help="Compare the first 16-64 bytes of a native resource and generated candidate with annotations.",
    )
    header_compare_parser.add_argument("--native", type=Path, required=True, help="Known native local RSC resource.")
    header_compare_parser.add_argument("--generated", type=Path, required=True, help="Generated candidate resource.")
    header_compare_parser.add_argument(
        "--bytes",
        type=int,
        default=64,
        help="Number of leading bytes to compare. Must be 16-64. Default: 64.",
    )
    header_compare_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    layout_compare_parser = subparsers.add_parser(
        "compare-resource-layouts",
        help="Compare native/generated layout metadata, page semantics, raw header diffs, and mutation probes.",
    )
    layout_compare_parser.add_argument("--native", type=Path, required=True, help="Known native local RSC resource.")
    layout_compare_parser.add_argument("--generated", type=Path, required=True, help="Generated candidate resource.")
    layout_compare_parser.add_argument(
        "--bytes",
        type=int,
        default=64,
        help="Number of leading bytes to diff. Must be 16-64. Default: 64.",
    )
    layout_compare_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    relocation_parser = subparsers.add_parser(
        "compare-relocations",
        help="Summarize or compare relocation/fixup topology from generated manifests or inferred resource maps.",
    )
    relocation_parser.add_argument("--left", type=Path, required=True, help="Left/generated/native .ydr path.")
    relocation_parser.add_argument("--right", type=Path, default=None, help="Optional right .ydr path to compare.")
    relocation_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    page_domain_parser = subparsers.add_parser(
        "classify-page-domains",
        help="Classify serialized object page domains as system, graphics, or shared/unknown.",
    )
    page_domain_parser.add_argument("file", type=Path, help="Generated or inspectable .ydr path.")
    page_domain_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    mutation_matrix_parser = subparsers.add_parser(
        "mutation-matrix",
        help="Analyze controlled fixture variants and classify mutation-sensitive fields.",
    )
    mutation_matrix_parser.add_argument(
        "manifest",
        type=Path,
        nargs="?",
        default=Path("tests/fixtures/controlled_ydr_variants/manifest.json"),
        help="Manifest JSON path or variant directory. Defaults to controlled fixture manifest.",
    )
    mutation_matrix_parser.add_argument("--baseline", default="baseline_triangle", help="Baseline variant name.")
    mutation_matrix_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    native_ydr_parser = subparsers.add_parser(
        "find-native-ydr-candidates",
        help="Scan local roots for loose .ydr candidates and classify native-oracle suitability.",
    )
    native_ydr_parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        default=[Path("E:/Red Dead Redemption 2"), Path(".")],
        help="Roots to scan. Defaults to local RDR2 install and project directory.",
    )
    native_ydr_parser.add_argument("--max-files", type=int, default=None, help="Maximum .ydr files to inspect.")
    native_ydr_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")

    native_reference_parser = subparsers.add_parser(
        "native-rsc8-reference",
        help="Build a native RSC8 evidence report without assuming legacy RSC7 page semantics.",
    )
    native_reference_parser.add_argument("file", type=Path, help="Native loose RSC8 resource path.")
    native_reference_parser.add_argument("--json", action="store_true", help="Print JSON instead of text.")
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    known_commands = {
        "inspect",
        "make-fixture",
        "pack-ydr-xml",
        "summarize-ydr-xml",
        "write-ydr-xml-structures",
        "compare-ydr-structures",
        "scan-rpf8",
        "extract-rpf8-ydr",
        "decode-rpf8-toc",
        "stage-lml-mask",
        "analyze-rsc8-corpus",
        "detect-native-ydr-tools",
        "compare-resource-headers",
        "compare-resource-layouts",
        "compare-relocations",
        "classify-page-domains",
        "mutation-matrix",
        "find-native-ydr-candidates",
        "native-rsc8-reference",
        "-h",
        "--help",
    }
    if argv and argv[0] not in known_commands:
        argv = ["inspect", *argv]

    args = build_arg_parser().parse_args(argv)
    if args.command is None:
        build_arg_parser().print_help()
        return 2

    if args.command == "make-fixture":
        path = write_sample_fixture(args.out)
        print(f"Wrote fixture: {path.resolve()}")
        if args.verify:
            print()
            print_text(
                inspect_file(path, max_entries=100_000, string_limit=0, debug=args.debug),
                show_resource_map=args.resource_map,
            )
        return 0

    if args.command == "pack-ydr-xml":
        if not args.xml.is_file():
            print(f"error: XML source not found: {args.xml}", file=sys.stderr)
            return 2
        try:
            path, counts = pack_ydr_xml(args.xml, args.out, version=args.version)
        except (ElementTree.ParseError, ParseError) as exc:
            print(f"error: could not pack XML metadata: {exc}", file=sys.stderr)
            return 1
        print(f"Packed metadata-only YDR: {path.resolve()}")
        print(
            "Source model counts: "
            f"high={counts.high}, medium={counts.medium}, "
            f"low={counts.low}, very_low={counts.very_low}"
        )
        print("Note: this is an inspectable packer skeleton, not a game-ready mesh/resource pack.")
        if args.verify:
            print()
            print_text(
                inspect_file(path, max_entries=100_000, string_limit=0, debug=args.debug),
                show_resource_map=args.resource_map,
            )
        return 0

    if args.command == "summarize-ydr-xml":
        if not args.xml.is_file():
            print(f"error: XML source not found: {args.xml}", file=sys.stderr)
            return 2
        try:
            drawable = parse_drawable_xml(args.xml)
        except (ElementTree.ParseError, ParseError, ValueError) as exc:
            print(f"error: could not parse drawable XML: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(drawable), indent=2))
        else:
            print_drawable_xml_summary(drawable)
        return 0

    if args.command == "write-ydr-xml-structures":
        if not args.xml.is_file():
            print(f"error: XML source not found: {args.xml}", file=sys.stderr)
            return 2
        try:
            report = write_ydr_xml_structures(
                args.xml,
                args.out,
                version=args.version,
                endian=args.endian,
                resource_format=args.resource_format,
            )
        except (ElementTree.ParseError, ParseError, ValueError, struct.error) as exc:
            print(f"error: could not write drawable structures: {exc}", file=sys.stderr)
            return 1
        print_binary_write_report(report)
        print("Note: structure headers, object placement, pointer fixups, PNXCT vertex/index declaration metadata, shader parameter side tables, and source texture payloads are written; native RDR2 shader binding offsets and GPU texture surface encoding still need sample-based confirmation.")
        if args.verify:
            print()
            inspection = inspect_file(args.out, max_entries=100_000, string_limit=0)
            print_text(inspection, show_resource_map=args.resource_map)
        return 0

    if args.command == "compare-ydr-structures":
        if not args.known_good.is_file():
            print(f"error: known-good file not found: {args.known_good}", file=sys.stderr)
            return 2
        if not args.candidate.is_file():
            print(f"error: candidate file not found: {args.candidate}", file=sys.stderr)
            return 2
        try:
            known_good = extract_ydr_structure_snapshot(args.known_good)
            candidate = extract_ydr_structure_snapshot(args.candidate)
            comparison = compare_ydr_structure_snapshots(known_good, candidate)
        except ParseError as exc:
            print(f"error: could not compare YDR structures: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(comparison), indent=2))
        else:
            if args.dump_known_good:
                print_ydr_structure_snapshot(known_good)
                print()
            if args.dump_candidate:
                print_ydr_structure_snapshot(candidate)
                print()
            print_ydr_structure_comparison(comparison, only_diffs=args.only_diffs)
        return 0

    if args.command == "scan-rpf8":
        if not args.path.exists():
            print(f"error: path not found: {args.path}", file=sys.stderr)
            return 2
        if args.max_files is not None and args.max_files < 0:
            print("error: --max-files must be non-negative", file=sys.stderr)
            return 2
        results = scan_rpf8_path(args.path, scan_signatures=not args.no_signatures, max_files=args.max_files)
        if args.json:
            print(json.dumps(to_jsonable([{"path": str(path), "header": header} for path, header in results]), indent=2))
        else:
            print_rpf8_scan(results)
        return 0

    if args.command == "extract-rpf8-ydr":
        if not args.game_root.exists():
            print(f"error: game root not found: {args.game_root}", file=sys.stderr)
            return 2
        if args.max_files is not None and args.max_files < 0:
            print("error: --max-files must be non-negative", file=sys.stderr)
            return 2
        extracted, messages = try_extract_known_good_ydr_from_rpf8(args.game_root, args.out, max_files=args.max_files)
        for message in messages:
            print(message)
        if extracted is None:
            print(
                "No known-good .ydr was extracted. Next required layer: real RPF8 TOC decryption/decompression and entry decoding.",
                file=sys.stderr,
            )
            return 1
        print(f"Extracted: {extracted.resolve()}")
        return 0

    if args.command == "decode-rpf8-toc":
        if not args.toc.is_file():
            print(f"error: TOC file not found: {args.toc}", file=sys.stderr)
            return 2
        if args.limit < 0:
            print("error: --limit must be non-negative", file=sys.stderr)
            return 2
        try:
            report = decode_rpf8_toc_blob(
                args.toc,
                entry_count=args.entry_count,
                entry_size=args.entry_size,
                names_offset=args.names_offset,
                max_entries=args.max_entries,
            )
        except ParseError as exc:
            print(f"error: could not decode RPF8 TOC: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_rpf8_toc_decode_report(report, limit=args.limit)
        return 0

    if args.command == "stage-lml-mask":
        if not args.xml.is_file():
            print(f"error: XML source not found: {args.xml}", file=sys.stderr)
            return 2
        try:
            report = stage_lml_mask(
                args.xml,
                args.package,
                update_install_xml=not args.no_install_update,
                version=args.version,
                endian=args.endian,
                resource_format=args.resource_format,
            )
        except (ElementTree.ParseError, ParseError, ValueError, struct.error) as exc:
            print(f"error: could not stage LML mask: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_lml_stage_report(report)
        return 0

    if args.command == "analyze-rsc8-corpus":
        if not args.root.exists():
            print(f"error: root not found: {args.root}", file=sys.stderr)
            return 2
        report = analyze_rsc8_corpus(args.root)
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_rsc8_corpus_report(report)
        return 0

    if args.command == "detect-native-ydr-tools":
        roots = args.root if args.root else None
        report = detect_native_ydr_tools(roots)
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_native_ydr_tool_report(report)
        return 0

    if args.command == "compare-resource-headers":
        try:
            report = compare_resource_headers(args.native, args.generated, byte_count=args.bytes)
        except ParseError as exc:
            print(f"error: could not compare headers: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_header_comparison_report(report)
        return 0

    if args.command == "compare-resource-layouts":
        try:
            report = compare_resource_layouts(args.native, args.generated, byte_count=args.bytes)
        except ParseError as exc:
            print(f"error: could not compare layouts: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_resource_layout_comparison_report(report)
        return 0

    if args.command == "compare-relocations":
        try:
            report = compare_relocations(args.left, args.right) if args.right else summarize_relocations(args.left)
        except ParseError as exc:
            print(f"error: could not compare relocations: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        elif isinstance(report, RelocationComparisonReport):
            print_relocation_comparison(report)
        else:
            print_relocation_summary(report)
        return 0

    if args.command == "classify-page-domains":
        try:
            report = page_domain_report(args.file)
        except ParseError as exc:
            print(f"error: could not classify page domains: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_page_domain_report(report)
        return 0

    if args.command == "mutation-matrix":
        try:
            report = build_mutation_matrix(args.manifest, baseline_variant=args.baseline)
        except (ParseError, OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"error: could not build mutation matrix: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_mutation_matrix(report)
        return 0

    if args.command == "find-native-ydr-candidates":
        if args.max_files is not None and args.max_files < 0:
            print("error: --max-files must be non-negative", file=sys.stderr)
            return 2
        report = find_native_ydr_candidates(args.roots, max_files=args.max_files)
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_native_ydr_candidate_report(report)
        return 0

    if args.command == "native-rsc8-reference":
        try:
            report = native_rsc8_reference_report(args.file)
        except ParseError as exc:
            print(f"error: could not build native RSC8 reference: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(to_jsonable(report), indent=2))
        else:
            print_native_rsc8_reference_report(report)
        return 0

    if not args.file.is_file():
        print(f"error: not a file: {args.file}", file=sys.stderr)
        return 2
    if args.max_entries < 0:
        print("error: --max-entries must be non-negative", file=sys.stderr)
        return 2
    if args.strings < 0:
        print("error: --strings must be non-negative", file=sys.stderr)
        return 2

    if args.hex_window < 0:
        print("error: --hex-window must be non-negative", file=sys.stderr)
        return 2

    inspection = inspect_file(
        args.file,
        max_entries=args.max_entries,
        string_limit=args.strings,
        trace=args.trace,
        debug=args.debug,
        hex_window_size=args.hex_window,
    )
    if args.json:
        print(json.dumps(to_jsonable(inspection), indent=2))
    else:
        print_text(inspection, show_resource_map=args.resource_map)
    return 1 if any(issue.severity == "error" for issue in inspection.issues) else 0


if __name__ == "__main__":
    raise SystemExit(main())
