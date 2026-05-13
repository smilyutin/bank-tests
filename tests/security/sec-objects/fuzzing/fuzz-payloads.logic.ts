export type FuzzPayload = { name: string; value: any };

// Build a mixed payload set that exercises type confusion, injections, and size limits.
export function generateFuzzPayloads(): FuzzPayload[] {
  return [
    // Extreme numeric values
    { name: 'max_int', value: 2147483647 },
    { name: 'min_int', value: -2147483648 },
    { name: 'overflow_int', value: 999999999999999999999 },
    { name: 'negative_zero', value: -0 },
    { name: 'infinity', value: Number.POSITIVE_INFINITY },
    { name: 'negative_infinity', value: Number.NEGATIVE_INFINITY },
    { name: 'nan', value: NaN },

    // Type confusion
    { name: 'boolean_as_string', value: 'true' },
    { name: 'number_as_string', value: '123' },
    { name: 'null_value', value: null },
    { name: 'undefined_value', value: undefined },
    { name: 'empty_object', value: {} },
    { name: 'empty_array', value: [] },
    { name: 'nested_arrays', value: [[[[[]]]]] },

    // String edge cases
    { name: 'empty_string', value: '' },
    { name: 'whitespace', value: '   ' },
    { name: 'null_byte', value: '\0' },
    { name: 'newlines', value: '\n\n\n\n\n' },
    { name: 'tabs', value: '\t\t\t\t' },
    { name: 'unicode_emoji', value: '😀😁😂🤣😃😄😅😆' },
    { name: 'unicode_rtl', value: '\u202E\u202D' },
    { name: 'control_chars', value: '\x00\x01\x02\x03\x04\x05' },

    // Very long strings
    { name: 'long_string_1k', value: 'A'.repeat(1000) },
    { name: 'long_string_10k', value: 'B'.repeat(10000) },
    { name: 'long_string_100k', value: 'C'.repeat(100000) },

    // Format strings and injections
    { name: 'format_string', value: '%s%s%s%s%s%s%s%s' },
    { name: 'sql_injection', value: "' OR '1'='1" },
    { name: 'nosql_injection', value: { $ne: null } },
    { name: 'command_injection', value: '; ls -la' },
    { name: 'path_traversal', value: '../../../etc/passwd' },
    { name: 'xss_script', value: '<script>alert(1)</script>' },
    { name: 'xxe_payload', value: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' },

    // Arrays with unusual content
    { name: 'array_of_nulls', value: [null, null, null] },
    { name: 'mixed_types', value: [1, 'two', null, true, {}, []] },
    { name: 'deeply_nested', value: { a: { b: { c: { d: { e: { f: 'deep' } } } } } } },

    // Special numeric formats
    { name: 'scientific_notation', value: 1.23e+100 },
    { name: 'hex_string', value: '0x1234567890ABCDEF' },
    { name: 'octal_string', value: '0o777' },
    { name: 'binary_string', value: '0b11111111' },
  ];
}

export function isJsonTransportableValue(value: any): boolean {
  if (value === undefined) return false;
  if (typeof value === 'number' && !Number.isFinite(value)) return false;
  return true;
}
