# Vector generator

The Rust-based `gen_vectors` binary (in slipstream-dns) builds DNS queries and
responses using A records. It reads `vectors.txt` and writes JSON to stdout.

The helper script `scripts/gen_vectors.sh` runs the Rust generator and writes
`fixtures/vectors/dns-vectors.json`. No C repo is required.

Format of `vectors.txt`:

```
name,id,domain,payload_hex[,mode,qname_override,error_rcode,raw_query_hex]
```

- `payload_hex` may be `-` for an empty payload (only valid with `mode != normal`).
- `mode` defaults to `normal`.
- `qname_override` is required for `invalid_base32`, `suffix_mismatch`, and `empty_subdomain`, and must include a trailing dot.
- `raw_query_hex` is required for `raw_query_hex` mode and is interpreted as a hex-encoded UDP payload.
- Use `-` as a placeholder to skip optional fields (the CSV parser does not preserve empty fields).
- `error_rcode` is optional; when set, `response_error` is emitted. Defaults are used for `invalid_base32` and `suffix_mismatch`.

Built-in modes:

- `normal`
- `invalid_base32`
- `suffix_mismatch`
- `non_a` (TXT query when A is expected -> NAME_ERROR)
- `empty_subdomain`
- `qdcount_zero`
- `not_query`
- `raw_query_hex`

Typical use:

```
./scripts/gen_vectors.sh
```

This compiles the generator against the slipstream C repo at `../slipstream`
(override with `SLIPSTREAM_DIR`) and requires the C repo submodules to be
initialized.
