# Rockstar Resource Inspector

Read-only CLI for inspecting known-good Rockstar/RAGE resource files and archives.

It currently recognizes:

- `RSC7` resource headers used by extracted/OpenIV-compatible resource files such as `.ytd`, `.ydr`, `.ydd`, `.yft`, `.ybn`, and related formats.
- `.ydr` drawable model-list metadata, including section-aware resource pointer mapping for `0x50000000` system and `0x60000000` graphics addresses.
- `RPF7` GTA V archives when the table of contents is unencrypted (`NONE` or `OPEN`). Encrypted archive TOCs are identified but not decoded.

The tool validates offsets and lengths before reads, rejects excessive entry counts, and does not extract or modify file content.

## Usage

```powershell
python .\rockstar_resource_inspector.py .\example.ytd
python .\rockstar_resource_inspector.py .\example.ytd --json
python .\rockstar_resource_inspector.py .\example.rpf --strings 20
```

The explicit inspect form is also supported:

```powershell
python .\rockstar_resource_inspector.py inspect .\example.ydr
```

Debug and trace modes expose parser decisions and local byte context:

```powershell
python .\rockstar_resource_inspector.py inspect .\example.ydr --trace
python .\rockstar_resource_inspector.py inspect .\example.ydr --debug --hex-window 64
python .\rockstar_resource_inspector.py inspect .\example.ydr --resource-map
```

`--trace` prints structured parse events such as header reads, pointer resolution, and validated list arrays. `--debug` includes trace output plus hex windows around important offsets or parse warnings.
`--resource-map` prints a pointer resolution graph and a resource boundary validation summary.

## Fixture Generation

Write and immediately verify a safe synthetic `.ydr` fixture:

```powershell
python .\rockstar_resource_inspector.py make-fixture --verify
```

This writes:

```text
tests\fixtures\sample_drawable_3_models.ydr
```

For a `.ydr`, the top-level output now includes:

```text
Magic: 0x37435352
Version: 165
Drawable Models: 3
```

## XML Metadata Packing

Start from the existing mask XML export and write an inspectable metadata-only `.ydr` skeleton:

```powershell
python .\rockstar_resource_inspector.py pack-ydr-xml --verify
```

Default XML source:

```text
C:\Users\zlinz\OneDrive\Desktop\RDR2 Skinning\build\rdr2_mask_export\p_humanskinmask01x.ydr.xml
```

Default output:

```text
tests\fixtures\p_humanskinmask01x.metadata.ydr
```

This stage preserves the RSC7 wrapper, version, section-sized resource boundaries, virtual resource pointer layout, drawable LOD model-list headers, and XML-derived model counts. It does not yet serialize game-ready geometry, shaders, textures, skeletons, hash tables, or full pointer fixups.

## Drawable XML Summary

Parse the existing mask `.ydr.xml` into typed Python objects and print a structured summary:

```powershell
python .\rockstar_resource_inspector.py summarize-ydr-xml
```

The parser builds:

- `DrawableXml`
- `ShaderGroupXml`
- `DrawableModelXml`
- `DrawableGeometryXml`
- `VertexBufferXml`
- `IndexBufferXml`

For the current mask XML, the summary is:

```text
Name: p_humanskinmask01x
Models: 1
Geometries: 1
Vertices: 34407
Indices: 34860
Shader: default
Texture: p_humanskinmask01x_diffuse
Vertex Layout: PNXCT
```

## Binary Structure Writing

Write fixed-layout binary structures from the drawable XML:

```powershell
python .\rockstar_resource_inspector.py write-ydr-xml-structures --verify --resource-map
```

Default output:

```text
tests\fixtures\p_humanskinmask01x.structured.ydr
```

This stage writes headers, field order, padding, alignment, object placement, and pointer fixups for:

- `ShaderGroup`
- `TextureDictionary`
- `ShaderFX`
- `DrawableModel`
- `DrawableGeometry`
- `VertexBuffer`
- `IndexBuffer`
- `VertexData`
- `ShaderParameterTable`
- `TexturePayload`

The generated resource now maps through:

```text
Drawable
|-- ShaderGroup
|-- DrawableModelsHigh
    \-- DrawableModel
        \-- DrawableGeometry
            |-- VertexBuffer
            |-- IndexBuffer
            \-- VertexData
```

The writer now parses XML vertex rows and index lists, calculates the PNXCT logical stride, binds vertex/index declaration metadata, respects the XML `NonInterleaved` flag, writes vertex data into the graphics section, and writes indices into the graphics section with little-endian packing by default:

```powershell
python .\rockstar_resource_inspector.py write-ydr-xml-structures --endian little --verify --resource-map
```

For `PNXCT`, the current stream layout is:

```text
P: position, 3 float32
N: normal, 4 float32
X: tangent, 4 float32
C: color, 4 uint8
T: uv, 2 float32
Logical stride: 56 bytes
```

Shader XML parameters are parsed into typed texture, sampler, and CBuffer entries and emitted into a structured `ShaderParameterTable`. Texture dictionary entries now discover source `.png`/`.dds` files beside the XML export and serialize the source payload with dimensions where possible.

Current remaining writer warnings are intentional: native RDR2 ShaderFX binding offsets and GPU texture mip/surface encoding still require sample-based confirmation before these files should be treated as game-ready assets.

### Index Buffer Packing

Index packing is now explicit instead of a loose byte dump:

- Uses 16-bit indices when the parsed maximum index fits in `uint16`.
- Uses 32-bit indices when any index is above `65535`.
- Validates index count, negative values, `uint32` overflow, triangle-list alignment, triangle count, and vertex reference bounds.
- Places index data in the graphics section on a 16-byte boundary.
- Records index structure metadata in the write report: index width, index count, triangle count, max index, data size, endian, and alignment.

The CLI report shows index metadata next to `IndexData` and `IndexBuffer` objects so fixture output can be verified without opening the binary in a hex editor.

## Known-Good Binary Comparison

Once you have an extracted working RDR2 `.ydr`, compare it against the generated candidate:

```powershell
python .\rockstar_resource_inspector.py compare-ydr-structures `
  --known-good C:\path\to\known_good.ydr `
  --candidate .\tests\fixtures\p_humanskinmask01x.structured.ydr `
  --only-diffs
```

Add `--dump-known-good` or `--dump-candidate` to print field offsets, observed meanings, raw prefixes, pointer values, counts, and unknown non-zero byte counts for each mapped structure. This is the main workflow for replacing remaining safe placeholders with confirmed RDR2 field values.

Find local native `.ydr` candidates:

```powershell
python .\rockstar_resource_inspector.py find-native-ydr-candidates `
  "E:\Red Dead Redemption 2" `
  .
```

This command classifies loose `.ydr` files as possible native oracles, project-generated candidates, weak candidates, or rejects. It intentionally excludes this project's generated fixtures from `best_candidates`, because internally consistent output must not be treated as native evidence.

Current local result: no confirmed native minimal `.ydr` candidate was found. The only loose `.ydr` files detected are generated by this project, including the staged LML mask and controlled fixture variants.

Current canonical native reference:

```text
tests/known_good/native_minimal/p_tree_redwood_05.ydr
```

Run the native evidence report:

```powershell
python .\rockstar_resource_inspector.py native-rsc8-reference `
  .\tests\known_good\native_minimal\p_tree_redwood_05.ydr
```

Current finding for this native tree drawable: it is a strong loose RSC8 `.ydr` reference, but the payload is transformed/compressed/encrypted relative to the runtime pointer graph. The current parser can confirm the wrapper/header evidence and entropy profile, but cannot yet extract Drawable/ShaderGroup/VertexBuffer object ordering from the transformed payload.

After a trusted native RDR2 writer exports a tiny `.ydr`, place it under:

```text
tests/known_good/native_minimal/
```

Then run:

```powershell
python .\rockstar_resource_inspector.py find-native-ydr-candidates `
  .\tests\known_good\native_minimal

python .\rockstar_resource_inspector.py compare-resource-headers `
  --native .\tests\known_good\native_minimal\<native>.ydr `
  --generated .\tests\fixtures\controlled_ydr_variants\baseline_triangle\baseline_triangle.rsc8.ydr `
  --bytes 64

python .\rockstar_resource_inspector.py compare-resource-layouts `
  --native .\tests\known_good\native_minimal\<native>.ydr `
  --generated .\tests\fixtures\controlled_ydr_variants\baseline_triangle\baseline_triangle.rsc8.ydr `
  --bytes 64

python .\rockstar_resource_inspector.py compare-relocations `
  --left .\tests\known_good\native_minimal\<native>.ydr `
  --right .\tests\fixtures\controlled_ydr_variants\baseline_triangle\baseline_triangle.rsc8.ydr
```

## Tiny Triangle Pipeline Fixture

A minimal Blender-backed triangle fixture can be regenerated with:

```powershell
& "C:\Program Files\Blender Foundation\Blender 5.1\blender.exe" --background `
  --python .\tools\create_triangle_rage_sample.py -- `
  --out .\tests\fixtures\triangle_rage_sample
```

This writes:

- `tests/fixtures/triangle_rage_sample/triangle_rage_sample.blend`
- `tests/fixtures/triangle_rage_sample/triangle_rage_sample.ydr.xml`

Compile the XML into the current structured RSC8 candidate:

```powershell
python .\rockstar_resource_inspector.py write-ydr-xml-structures `
  --xml .\tests\fixtures\triangle_rage_sample\triangle_rage_sample.ydr.xml `
  --out .\tests\fixtures\triangle_rage_sample\triangle_rage_sample.rsc8.ydr `
  --resource-format rsc8 `
  --verify `
  --resource-map
```

Expected summary:

```text
Name: triangle_rage_sample
Models: 1
Geometries: 1
Vertices: 3
Indices: 3
Shader: default
Texture: triangle_rage_sample_diffuse
Vertex Layout: PNXCT
```

The generated `.ydr` is still an experimental packer output, not a confirmed native RDR2 writer output. Check local native writer availability with:

```powershell
python .\rockstar_resource_inspector.py detect-native-ydr-tools
```

Compare raw native/generated resource headers with annotations:

```powershell
python .\rockstar_resource_inspector.py compare-resource-headers `
  --native "E:\Red Dead Redemption 2\lml\downloader\RampageFiles\Textures\Textures.ytd" `
  --generated .\tests\fixtures\triangle_rage_sample\triangle_rage_sample.rsc8.ydr `
  --bytes 64
```

This prints raw native bytes, generated bytes, XOR bytes, byte-level equality marks, and field annotations:

- `known`: confirmed shared surface, currently only the `RSC8` magic.
- `unknown`: native RSC8 words whose exact writer semantics are not confirmed.
- `inferred`: generated experimental wrapper values, such as legacy-compatible version/page words.
- `changing`: payload-prefix bytes expected to differ across resource type, object layout, compression/encryption state, or writer output.

Current local native samples are loose `.ytd` texture dictionaries, not native `.ydr` drawables, so header comparisons against them are useful for RSC8 wrapper behavior only.

Compare layout metadata and page semantics with mutation probes:

```powershell
python .\rockstar_resource_inspector.py compare-resource-layouts `
  --native "E:\Red Dead Redemption 2\lml\downloader\RampageFiles\Textures\Textures.ytd" `
  --generated .\tests\fixtures\triangle_rage_sample\triangle_rage_sample.rsc8.ydr `
  --bytes 64
```

This includes:

- raw native/generated/XOR header bytes
- native and generated payload/layout metadata
- decoded generated system/graphics virtual sections
- annotated page-word semantics
- speculative legacy decodes for native RSC8 words, clearly marked as probes
- controlled mutations that swap individual words and full word triplets between native and generated headers

The current mutation results show that the generated file's RSC8 layout is entirely driven by the experimental legacy-compatible word triplet. Native `.ytd` RSC8 words remain `raw-rsc8` under this parser, so the native page-size derivation is still unresolved.

Generate controlled XML/RSC8 variants for one-variable-at-a-time parity analysis:

```powershell
python .\tools\create_controlled_ydr_variants.py `
  --out .\tests\fixtures\controlled_ydr_variants `
  --resource-format rsc8
```

Generated variants:

- `baseline_triangle`
- `plus_one_vertex`
- `plus_one_triangle`
- `uv_modification`
- `with_texture_payload`
- `second_geometry`
- `second_material`

Each variant writes an XML source, an experimental RSC8 `.ydr`, and a `manifest.json` entry containing writer object placement, fixups, vertex/index metadata, and warnings. Current generated/generated comparisons intentionally keep the same fixed 8 KB system and 8 KB graphics pages; object metadata changes before page words change. Native parity work should use this fixture set as soon as matching native exports are available.

Relocation/fixup topology can be inspected from generated manifests or inferred from parsed pointer graphs:

```powershell
python .\rockstar_resource_inspector.py compare-relocations `
  --left .\tests\fixtures\controlled_ydr_variants\baseline_triangle\baseline_triangle.rsc8.ydr

python .\rockstar_resource_inspector.py compare-relocations `
  --left .\tests\fixtures\controlled_ydr_variants\baseline_triangle\baseline_triangle.rsc8.ydr `
  --right .\tests\fixtures\controlled_ydr_variants\second_geometry\second_geometry.rsc8.ydr
```

The relocation report includes exact/inferred counts, relocation density, section-pair counts, page-crossing pointers, missing/extra relocation signatures, and ordering differences. Generated manifests are `HIGH_CONFIDENCE`; native resources are currently inferred from pointer graphs until the native relocation table format is confirmed.

Classify page domains:

```powershell
python .\rockstar_resource_inspector.py classify-page-domains `
  .\tests\fixtures\controlled_ydr_variants\second_material\second_material.rsc8.ydr
```

Current generated page-domain intent:

```text
ShaderGroup          -> system
DrawableModel        -> system
DrawableGeometry     -> system
VertexBuffer         -> system
IndexBuffer          -> system
VertexData           -> graphics
IndexData            -> graphics
TexturePayload       -> graphics
```

Build the mutation-sensitive field matrix:

```powershell
python .\rockstar_resource_inspector.py mutation-matrix `
  .\tests\fixtures\controlled_ydr_variants\manifest.json
```

Current findings:

- `file_size`, `system_page_size`, and `graphics_page_size` remain constant because the experimental writer still pads to fixed 8 KB system and graphics pages.
- `vertex_data_size` changes with vertex growth and geometry duplication.
- `index_data_size` changes with index growth and geometry duplication.
- `fixup_count` and `page_crossing_fixups` change with topology/material expansion.
- `second_material` currently exposes duplicate zero-sized missing texture payload pointers; this is reported as a warning and should not be treated as native-correct topology.

## RPF8 TOC Work

RDR2 install archives are detected as `RPF8` (`8FPR`). The current scanner parses the header guesses, nested RPF8 signatures, validated raw `RSC7` hits, and likely TOC regions:

```powershell
python .\rockstar_resource_inspector.py scan-rpf8 "E:\Red Dead Redemption 2\common_0.rpf"
```

The TOC analysis reports entropy, printable/zero ratios, zlib/raw-deflate probe status, plaintext entry plausibility for 16-byte and 20-byte entries, and a transform inference. On the local install tested so far, likely TOC regions are high-entropy, do not inflate with standard zlib/deflate, and do not look like plaintext entries. The current inference is: encrypted RPF8 TOC, likely an AES-family stream/block transform before entry decoding. That means actual `.ydr` extraction still requires obtaining/deriving the legitimate local TOC decryption material, then decoding names, offsets, sizes, and resource flags.

If you have a legitimately obtained plaintext/decrypted TOC blob, decode the entries with:

```powershell
python .\rockstar_resource_inspector.py decode-rpf8-toc `
  --toc .\tests\known_good\decrypted_common_0.toc `
  --entry-count 1586 `
  --entry-size 16
```

This command does not derive or bypass archive encryption. It parses an already-decoded TOC into candidate directory, binary, and resource entries so `.ydr` offsets can be extracted once the protected TOC layer is handled outside this tool.

## RSC8 Support

The inspector now decodes RSC8 headers as raw three-word headers and reports whether the words are native/raw RDR2-style or the tool's experimental RSC8 wrapper:

```powershell
python .\rockstar_resource_inspector.py inspect "E:\Red Dead Redemption 2\lml\downloader\RampageFiles\Textures\Textures.ytd" --debug
```

The writer can emit an experimental RSC8 wrapper:

```powershell
python .\rockstar_resource_inspector.py write-ydr-xml-structures --resource-format rsc8 --verify --resource-map
```

`stage-lml-mask` now defaults to that RSC8 wrapper because local streamed RDR2 resources were observed as RSC8:

```powershell
python .\rockstar_resource_inspector.py stage-lml-mask
```

Important: generated RSC8 output currently uses RSC7-compatible page words under an RSC8 magic. Native RDR2 RSC8 page-word semantics are parsed as raw values but are not fully confirmed for writing yet.

Analyze all loose local RSC8 resources:

```powershell
python .\rockstar_resource_inspector.py analyze-rsc8-corpus "E:\Red Dead Redemption 2"
```

On the local install, only two distinct native loose RSC8 samples were found, both `.ytd` texture dictionaries. They share `word1=0x01000002`, `word2=0x00010000`, and `word3 low16=0x0002`. `word3 high16` differs between samples and does not match a simple file-size/page-count relationship, so drawable-specific RSC8 page semantics remain unconfirmed.

## Internal Parser Backbone

The parser now uses structured internal models for core binary concepts:

- `ResourceSection` and `ResourceLayout` for system/graphics section boundaries.
- `ResourceAddress` for resolved virtual pointers.
- `DrawableModelListInfo` for YDR LOD model-list headers.
- `ModelCounts` for XML-derived LOD counts.
- `ParseTraceEvent` and `HexWindow` for debug visibility.
- `ResourceMap`, `ResourceMapNode`, `ResourceMapEdge`, and `BoundaryValidation` for pointer graphing and boundary checks.

The YDR resource map currently resolves:

```text
Drawable
|-- ShaderGroup
|-- Skeleton
|-- Joints
|-- DrawableModelsHigh/Medium/Low/VeryLow
    |-- DrawableModel
        |-- ShaderMapping
        |-- Bounds
        |-- DrawableGeometry
            |-- VertexBuffer
            |-- IndexBuffer
            |-- BoneIds
            \-- VertexData
```

## Tests

```powershell
python -m unittest
```

## Notes

This is a metadata inspector, not a full asset decoder. It parses safe top-level structure, page flags, sizes, resource/archive type hints, `.ydr` drawable model-list counts, and optional printable strings. Full decoding of geometry, skeletons, shaders, texture dictionaries, hash references, and write-time pointer fixups can be layered on top of this once sample files and target metadata fields are available.
