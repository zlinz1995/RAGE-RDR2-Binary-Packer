import struct
import tempfile
import unittest
from pathlib import Path

from rockstar_resource_inspector import (
    build_metadata_ydr,
    compare_ydr_structure_snapshots,
    decode_rpf8_toc_blob,
    extract_ydr_structure_snapshot,
    inspect_file,
    pack_ydr_xml,
    parse_drawable_xml,
    write_ydr_xml_structures,
    write_sample_fixture,
)


def flags_from_units(units: int, version: int = 0, shift: int = 0) -> int:
    return ((version & 0xF) << 28) | ((units & 0x7F) << 17) | (shift & 0xF)


class RockstarResourceInspectorTests(unittest.TestCase):
    def write_temp(self, data: bytes, suffix: str) -> Path:
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        handle.write(data)
        handle.close()
        return Path(handle.name)

    def test_rsc7_header_is_decoded(self) -> None:
        system_flags = flags_from_units(1, version=1)
        graphics_flags = flags_from_units(2, version=2)
        path = self.write_temp(
            b"RSC7" + struct.pack("<III", 13, system_flags, graphics_flags) + b"payload",
            ".ytd",
        )
        try:
            result = inspect_file(path, max_entries=100, string_limit=0)
        finally:
            path.unlink()

        self.assertEqual(result.format, "RSC7 resource")
        self.assertEqual(result.guessed_resource_type, "Texture dictionary")
        self.assertEqual(result.header.version, 13)
        self.assertEqual(result.header.system_flags.decoded_size, 8192)
        self.assertEqual(result.header.graphics_flags.decoded_size, 16384)
        self.assertEqual(result.header.payload_size, 7)
        self.assertEqual(result.issues, [])

    def test_ydr_drawable_model_count_is_decoded_from_list_headers(self) -> None:
        system_flags = flags_from_units(1, version=1)
        graphics_flags = flags_from_units(0, version=2)
        payload = bytearray(8192)
        struct.pack_into("<IIQ", payload, 0, 1079456120, 1, 0)
        struct.pack_into("<Q", payload, 0x50, 0x50000100)
        struct.pack_into("<QHHI", payload, 0x100, 0x50000120, 3, 3, 0)
        struct.pack_into("<QQQ", payload, 0x120, 0x50000200, 0x500002A8, 0x50000350)
        path = self.write_temp(
            b"RSC7" + struct.pack("<III", 165, system_flags, graphics_flags) + bytes(payload),
            ".ydr",
        )
        try:
            result = inspect_file(path, max_entries=100, string_limit=0)
        finally:
            path.unlink()

        self.assertEqual(result.format, "RSC7 resource")
        self.assertEqual(result.header.version, 165)
        self.assertIsNotNone(result.ydr)
        self.assertEqual(result.ydr.drawable_models, 3)
        self.assertEqual(result.ydr.drawable_models_high, 3)
        self.assertEqual(result.issues, [])

    def test_fixture_generator_writes_inspectable_ydr(self) -> None:
        path = Path(tempfile.gettempdir()) / "sample_drawable_3_models.ydr"
        try:
            write_sample_fixture(path)
            result = inspect_file(path, max_entries=100, string_limit=0)
        finally:
            if path.exists():
                path.unlink()

        self.assertEqual(result.header.version, 165)
        self.assertEqual(result.ydr.drawable_models, 3)

    def test_pack_ydr_xml_writes_metadata_skeleton_from_counts(self) -> None:
        xml = self.write_temp(
            b"""<?xml version="1.0"?>
<RDR2Drawable version="1">
  <LodHigh><Models><Item /><Item /></Models></LodHigh>
  <LodMed><Models><Item /></Models></LodMed>
</RDR2Drawable>
""",
            ".ydr.xml",
        )
        out = Path(tempfile.gettempdir()) / "packed_metadata_mask.ydr"
        try:
            _, counts = pack_ydr_xml(xml, out)
            result = inspect_file(out, max_entries=100, string_limit=0)
        finally:
            xml.unlink()
            if out.exists():
                out.unlink()

        self.assertEqual(counts.high, 2)
        self.assertEqual(counts.medium, 1)
        self.assertEqual(result.ydr.drawable_models, 3)
        self.assertEqual(result.ydr.drawable_models_high, 2)
        self.assertEqual(result.ydr.drawable_models_medium, 1)

    def test_parse_drawable_xml_typed_summary(self) -> None:
        xml = self.write_temp(
            b"""<?xml version="1.0"?>
<RDR2Drawable version="1">
  <Name>p_humanskinmask01x</Name>
  <Hash>p_humanskinmask01x</Hash>
  <ShaderGroup>
    <TextureDictionary version="1"><Textures><Item><Name>p_humanskinmask01x_diffuse</Name></Item></Textures></TextureDictionary>
    <Shaders><Item><Name>default</Name></Item></Shaders>
  </ShaderGroup>
  <LodHigh><Models><Item>
    <Flags value="0" />
    <HasSkin value="false" />
    <BoneIndex value="0" />
    <BonesCount value="0" />
    <Geometries><Item>
      <ShaderID value="0" />
      <VertexLayout>
        <Formats>39952</Formats>
        <NonInterleaved value="true" />
        <Semantics>PNXCT</Semantics>
      </VertexLayout>
      <Vertices>
        0 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 0
        1 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t1 0
        0 1 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 1
      </Vertices>
      <Indices>0 1 2</Indices>
    </Item></Geometries>
  </Item></Models></LodHigh>
</RDR2Drawable>
""",
            ".ydr.xml",
        )
        try:
            drawable = parse_drawable_xml(xml)
        finally:
            xml.unlink()

        self.assertEqual(drawable.name, "p_humanskinmask01x")
        self.assertEqual(drawable.model_count, 1)
        self.assertEqual(drawable.geometry_count, 1)
        self.assertEqual(drawable.vertex_count, 3)
        self.assertEqual(drawable.index_count, 3)
        self.assertEqual(drawable.primary_shader, "default")
        self.assertEqual(drawable.primary_texture, "p_humanskinmask01x_diffuse")
        self.assertEqual(drawable.primary_vertex_layout, "PNXCT")
        self.assertEqual(len(drawable.shader_group.shaders[0].parameters.items), 0)

    def test_write_ydr_xml_structures_outputs_pointer_mapped_resource(self) -> None:
        xml = self.write_temp(
            b"""<?xml version="1.0"?>
<RDR2Drawable version="1">
  <Name>p_humanskinmask01x</Name>
  <Hash>p_humanskinmask01x</Hash>
  <ShaderGroup>
    <TextureDictionary version="1"><Textures><Item><Name>p_humanskinmask01x_diffuse</Name></Item></Textures></TextureDictionary>
    <Shaders><Item><Name>default</Name></Item></Shaders>
  </ShaderGroup>
  <LodHigh><Models><Item>
    <Flags value="0" />
    <HasSkin value="false" />
    <BoneIndex value="0" />
    <BonesCount value="0" />
    <Geometries><Item>
      <ShaderID value="0" />
      <VertexLayout>
        <Formats>39952</Formats>
        <NonInterleaved value="true" />
        <Semantics>PNXCT</Semantics>
      </VertexLayout>
      <Vertices>
        0 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 0
        1 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t1 0
        0 1 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 1
      </Vertices>
      <Indices>0 1 2</Indices>
    </Item></Geometries>
  </Item></Models></LodHigh>
</RDR2Drawable>
""",
            ".ydr.xml",
        )
        out = Path(tempfile.gettempdir()) / "structured_mask.ydr"
        try:
            report = write_ydr_xml_structures(xml, out)
            result = inspect_file(out, max_entries=100, string_limit=0)
            raw = out.read_bytes()
        finally:
            xml.unlink()
            if out.exists():
                out.unlink()

        self.assertGreaterEqual(len(report.objects), 9)
        self.assertEqual(result.ydr.drawable_models, 1)
        edge_fields = {edge.field for edge in result.ydr.resource_map.edges}
        self.assertIn("ShaderGroup", edge_fields)
        self.assertIn("VertexBuffer", edge_fields)
        self.assertIn("IndexBuffer", edge_fields)
        vertex_data = next(item for item in report.objects if item.name == "VertexData[0:0]")
        vertex_start = 16 + report.system_size + vertex_data.offset
        positions = struct.unpack_from("<9f", raw, vertex_start)
        self.assertEqual(positions, (0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0))
        self.assertEqual(vertex_data.metadata["vertex_layout"], "PNXCT")
        self.assertEqual(vertex_data.metadata["stride"], 56)
        self.assertEqual(vertex_data.metadata["vertex_count"], 3)
        index_data = next(item for item in report.objects if item.name == "IndexData[0:0]")
        index_start = 16 + report.system_size + index_data.offset
        self.assertEqual(struct.unpack_from("<3H", raw, index_start), (0, 1, 2))
        self.assertEqual(index_data.metadata["index_size_bits"], 16)
        self.assertEqual(index_data.metadata["index_count"], 3)
        self.assertEqual(index_data.metadata["triangle_count"], 1)
        index_buffer = next(item for item in report.objects if item.name == "IndexBuffer[0:0]")
        self.assertEqual(index_buffer.metadata["index_size_bits"], 16)
        self.assertEqual(index_buffer.metadata["data_size"], 6)
        shader_fx = next(item for item in report.objects if item.name == "ShaderFX[0]")
        self.assertEqual(shader_fx.metadata["shader"], "default")
        self.assertEqual(shader_fx.metadata["shader_hash"], "0xE4DF46D5")

    def test_write_ydr_xml_structures_packs_32_bit_indices_when_needed(self) -> None:
        xml = self.write_temp(
            b"""<?xml version="1.0"?>
<RDR2Drawable version="1">
  <Name>wide_indices</Name>
  <Hash>wide_indices</Hash>
  <ShaderGroup>
    <TextureDictionary version="1"><Textures><Item><Name>wide_indices_diffuse</Name></Item></Textures></TextureDictionary>
    <Shaders><Item><Name>default</Name></Item></Shaders>
  </ShaderGroup>
  <LodHigh><Models><Item>
    <Flags value="0" />
    <HasSkin value="false" />
    <BoneIndex value="0" />
    <BonesCount value="0" />
    <Geometries><Item>
      <ShaderID value="0" />
      <VertexLayout>
        <Formats>39952</Formats>
        <NonInterleaved value="false" />
        <Semantics>PNXCT</Semantics>
      </VertexLayout>
      <Vertices>
        0 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 0
        1 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t1 0
        0 1 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 1
      </Vertices>
      <Indices>0 1 70000</Indices>
    </Item></Geometries>
  </Item></Models></LodHigh>
</RDR2Drawable>
""",
            ".ydr.xml",
        )
        out = Path(tempfile.gettempdir()) / "structured_wide_indices.ydr"
        try:
            report = write_ydr_xml_structures(xml, out)
            raw = out.read_bytes()
        finally:
            xml.unlink()
            if out.exists():
                out.unlink()

        index_data = next(item for item in report.objects if item.name == "IndexData[0:0]")
        index_start = 16 + report.system_size + index_data.offset
        self.assertEqual(struct.unpack_from("<3I", raw, index_start), (0, 1, 70000))
        self.assertEqual(index_data.metadata["index_size_bits"], 32)
        self.assertEqual(index_data.metadata["index_size_bytes"], 4)
        self.assertEqual(index_data.metadata["data_size"], 12)
        self.assertEqual(index_data.metadata["alignment"], 16)
        self.assertEqual(index_data.metadata["endian"], "little")
        self.assertTrue(any("references vertex 70000" in warning for warning in report.warnings))

    def test_write_ydr_xml_structures_can_emit_experimental_rsc8_wrapper(self) -> None:
        xml = self.write_temp(
            b"""<?xml version="1.0"?>
<RDR2Drawable version="1">
  <Name>rsc8_mask</Name>
  <Hash>rsc8_mask</Hash>
  <ShaderGroup><Shaders><Item><Name>default</Name></Item></Shaders></ShaderGroup>
  <LodHigh><Models><Item>
    <Flags value="0" /><HasSkin value="false" /><BoneIndex value="0" /><BonesCount value="0" />
    <Geometries><Item>
      <ShaderID value="0" />
      <VertexLayout><Formats>39952</Formats><NonInterleaved value="false" /><Semantics>PNXCT</Semantics></VertexLayout>
      <Vertices>
        0 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 0
        1 0 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t1 0
        0 1 0\t0 0 1 0\t1 0 0 1\t255 255 255 255\t0 1
      </Vertices>
      <Indices>0 1 2</Indices>
    </Item></Geometries>
  </Item></Models></LodHigh>
</RDR2Drawable>
""",
            ".ydr.xml",
        )
        out = Path(tempfile.gettempdir()) / "structured_rsc8_mask.ydr"
        try:
            report = write_ydr_xml_structures(xml, out, resource_format="rsc8")
            result = inspect_file(out, max_entries=100, string_limit=0)
        finally:
            xml.unlink()
            if out.exists():
                out.unlink()

        self.assertEqual(result.format, "RSC8 resource")
        self.assertEqual(result.header.interpretation, "experimental-rsc8-with-rsc7-page-words")
        self.assertEqual(result.ydr.drawable_models, 1)
        self.assertTrue(any("experimental RSC7-compatible page words" in warning for warning in report.warnings))

    def test_debug_mode_collects_trace_and_hex_windows(self) -> None:
        path = Path(tempfile.gettempdir()) / "sample_drawable_debug.ydr"
        try:
            write_sample_fixture(path)
            result = inspect_file(path, max_entries=100, string_limit=0, debug=True)
        finally:
            if path.exists():
                path.unlink()

        self.assertTrue(result.trace)
        self.assertTrue(result.hex_windows)
        self.assertTrue(any(event.label == "ydr.payload" for event in result.trace))
        self.assertTrue(any("RSC7 header" in window.label for window in result.hex_windows))

    def test_resource_map_tracks_model_geometry_vertex_and_index_pointers(self) -> None:
        data = bytearray(build_metadata_ydr({"high": 1}))
        payload_base = 16
        model_offset = payload_base + 0x400
        geometry_array_offset = payload_base + 0x500
        geometry_offset = payload_base + 0x600
        vertex_buffer_offset = payload_base + 0x700
        index_buffer_offset = payload_base + 0x740

        struct.pack_into("<Q", data, model_offset + 0x08, 0x50000500)
        struct.pack_into("<HH", data, model_offset + 0x10, 1, 1)
        struct.pack_into("<Q", data, geometry_array_offset, 0x50000600)
        struct.pack_into("<Q", data, geometry_offset + 0x18, 0x50000700)
        struct.pack_into("<Q", data, geometry_offset + 0x38, 0x50000740)

        path = self.write_temp(bytes(data), ".ydr")
        try:
            result = inspect_file(path, max_entries=100, string_limit=0)
        finally:
            path.unlink()

        resource_map = result.ydr.resource_map
        self.assertIsNotNone(resource_map)
        edge_fields = {edge.field for edge in resource_map.edges}
        node_types = {node.type for node in resource_map.nodes}
        self.assertIn("Geometries", edge_fields)
        self.assertIn("VertexBuffer", edge_fields)
        self.assertIn("IndexBuffer", edge_fields)
        self.assertIn("DrawableGeometry", node_types)
        self.assertIn("VertexBuffer", node_types)
        self.assertIn("IndexBuffer", node_types)
        self.assertFalse([item for item in resource_map.boundary_validations if item.status == "invalid"])

    def test_structure_snapshot_compares_confirmed_fields(self) -> None:
        path = Path(tempfile.gettempdir()) / "snapshot_compare_sample.ydr"
        try:
            write_sample_fixture(path)
            known_good = extract_ydr_structure_snapshot(path)
            candidate = extract_ydr_structure_snapshot(path)
            comparison = compare_ydr_structure_snapshots(known_good, candidate)
        finally:
            if path.exists():
                path.unlink()

        self.assertGreater(len(known_good.nodes), 0)
        self.assertFalse(comparison.missing_in_candidate)
        self.assertFalse(comparison.extra_in_candidate)
        self.assertTrue(comparison.rows)
        self.assertTrue(all(row.status == "match" for row in comparison.rows))

    def test_rpf7_open_toc_entries_are_decoded(self) -> None:
        names = b"\x00tex.ytd\x00"
        root = struct.pack("<IIII", 0, 0x7FFFFF00, 1, 1)
        resource = (
            struct.pack("<H", 1)
            + b"\x20\x00\x00"
            + bytes([4, 0, 0x80])
            + struct.pack("<II", flags_from_units(1), flags_from_units(0))
        )
        header = b"RPF7" + struct.pack("<III", 2, len(names), 0)
        path = self.write_temp(header + root + resource + names, ".rpf")
        try:
            result = inspect_file(path, max_entries=100, string_limit=0)
        finally:
            path.unlink()

        self.assertEqual(result.format, "RPF7 archive")
        self.assertEqual(result.header.entry_count, 2)
        self.assertEqual(result.header.entries[0].kind, "directory")
        self.assertEqual(result.header.entries[1].kind, "resource")
        self.assertEqual(result.header.entries[1].name, "tex.ytd")
        self.assertEqual(result.header.entries[1].file_offset_bytes, 2048)

    def test_rpf8_archives_are_identified_as_unsupported_for_extraction(self) -> None:
        path = self.write_temp(b"8FPR" + b"\x00" * 60, ".rpf")
        try:
            result = inspect_file(path, max_entries=100, string_limit=0)
        finally:
            path.unlink()

        self.assertEqual(result.format, "RPF8 archive")
        self.assertTrue(any("RPF8 archive detected" in issue.message for issue in result.issues))

    def test_rsc8_header_words_are_decoded_without_page_assumptions(self) -> None:
        path = self.write_temp(b"RSC8" + struct.pack("<III", 0x01000002, 0x00010000, 0x00170002) + b"\x00" * 32, ".ytd")
        try:
            result = inspect_file(path, max_entries=100, string_limit=0)
        finally:
            path.unlink()

        self.assertEqual(result.format, "RSC8 resource")
        self.assertEqual(result.header.word1, 0x01000002)
        self.assertEqual(result.header.word2, 0x00010000)
        self.assertEqual(result.header.word3, 0x00170002)
        self.assertEqual(result.header.interpretation, "raw-rsc8")

    def test_decode_rpf8_toc_blob_reads_plaintext_candidate_entries(self) -> None:
        names = b"\x00root\x00mask.ydr\x00"
        root = struct.pack("<IIII", 1, 0x7FFFFF00, 1, 1)
        resource = (
            struct.pack("<H", 6)
            + b"\x30\x00\x00"
            + bytes([8, 0, 0x80])
            + struct.pack("<II", flags_from_units(1), flags_from_units(2))
        )
        path = self.write_temp(root + resource + names, ".toc")
        try:
            report = decode_rpf8_toc_blob(path, entry_count=2)
        finally:
            path.unlink()

        self.assertEqual(report.entry_size, 16)
        self.assertFalse(report.warnings)
        self.assertEqual(report.entries[0].kind, "directory")
        self.assertEqual(report.entries[0].name, "root")
        self.assertEqual(report.entries[1].kind, "resource")
        self.assertEqual(report.entries[1].name, "mask.ydr")
        self.assertEqual(report.entries[1].size, 48)
        self.assertEqual(report.entries[1].file_offset_bytes, 4096)

    def test_rejects_oversized_entry_count(self) -> None:
        data = b"RPF7" + struct.pack("<III", 999, 0, 0)
        path = self.write_temp(data, ".rpf")
        try:
            result = inspect_file(path, max_entries=10, string_limit=0)
        finally:
            path.unlink()

        self.assertEqual(result.format, "RPF7 archive")
        self.assertEqual(result.issues[0].severity, "error")
        self.assertIn("exceeds max_entries", result.issues[0].message)


if __name__ == "__main__":
    unittest.main()
