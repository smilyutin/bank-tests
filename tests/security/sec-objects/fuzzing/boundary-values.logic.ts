export type BoundaryTestCase = { name: string; field: string; value: any; expectValid: boolean };

// Generate a spread of boundary cases across numbers, strings, arrays, and dates.
export function generateBoundaryTests(): BoundaryTestCase[] {
  return [
    // Integer boundaries
    { name: 'int32_max', field: 'age', value: 2147483647, expectValid: false },
    { name: 'int32_min', field: 'age', value: -2147483648, expectValid: false },
    { name: 'int32_max_plus_one', field: 'age', value: 2147483648, expectValid: false },
    { name: 'int64_max', field: 'value', value: 9223372036854775807, expectValid: false },
    { name: 'uint_max', field: 'count', value: 4294967295, expectValid: false },

    // Zero and near-zero
    { name: 'zero', field: 'age', value: 0, expectValid: true },
    { name: 'negative_one', field: 'age', value: -1, expectValid: false },
    { name: 'positive_one', field: 'age', value: 1, expectValid: true },
    { name: 'negative_zero', field: 'value', value: -0, expectValid: true },

    // Float boundaries
    { name: 'float_max', field: 'price', value: Number.MAX_VALUE, expectValid: false },
    { name: 'float_min', field: 'price', value: Number.MIN_VALUE, expectValid: true },
    { name: 'float_epsilon', field: 'price', value: Number.EPSILON, expectValid: true },
    { name: 'infinity', field: 'price', value: Infinity, expectValid: false },
    { name: 'neg_infinity', field: 'price', value: -Infinity, expectValid: false },
    { name: 'nan', field: 'price', value: NaN, expectValid: false },

    // String length boundaries
    { name: 'empty_string', field: 'username', value: '', expectValid: false },
    { name: 'single_char', field: 'username', value: 'a', expectValid: false },
    { name: 'max_username_255', field: 'username', value: 'a'.repeat(255), expectValid: false },
    { name: 'max_username_256', field: 'username', value: 'a'.repeat(256), expectValid: false },
    { name: 'very_long_1k', field: 'bio', value: 'x'.repeat(1000), expectValid: false },
    { name: 'very_long_10k', field: 'bio', value: 'y'.repeat(10000), expectValid: false },
    { name: 'very_long_100k', field: 'description', value: 'z'.repeat(100000), expectValid: false },

    // Email boundaries
    { name: 'min_email', field: 'email', value: 'a@b.c', expectValid: true },
    { name: 'long_email_64_local', field: 'email', value: 'a'.repeat(64) + '@example.com', expectValid: true },
    { name: 'long_email_65_local', field: 'email', value: 'a'.repeat(65) + '@example.com', expectValid: false },
    { name: 'long_email_254_total', field: 'email', value: 'a'.repeat(240) + '@example.com', expectValid: false },
    { name: 'email_at_boundary', field: 'email', value: 'test@' + 'a'.repeat(63) + '.com', expectValid: true },

    // Array boundaries
    { name: 'empty_array', field: 'tags', value: [], expectValid: true },
    { name: 'single_item_array', field: 'tags', value: ['tag1'], expectValid: true },
    { name: 'large_array_100', field: 'tags', value: Array(100).fill('tag'), expectValid: false },
    { name: 'large_array_1000', field: 'tags', value: Array(1000).fill('tag'), expectValid: false },

    // Null/undefined boundaries
    { name: 'null_value', field: 'middleName', value: null, expectValid: true },
    { name: 'undefined_value', field: 'suffix', value: undefined, expectValid: true },
    { name: 'null_email', field: 'email', value: null, expectValid: false },
    { name: 'undefined_password', field: 'password', value: undefined, expectValid: false },

    // Boolean edge cases
    { name: 'boolean_true', field: 'active', value: true, expectValid: true },
    { name: 'boolean_false', field: 'active', value: false, expectValid: true },
    { name: 'string_true', field: 'active', value: 'true', expectValid: false },
    { name: 'number_one_as_bool', field: 'active', value: 1, expectValid: false },
    { name: 'number_zero_as_bool', field: 'active', value: 0, expectValid: false },

    // Date boundaries
    { name: 'unix_epoch', field: 'birthdate', value: '1970-01-01', expectValid: true },
    { name: 'year_2038', field: 'expiry', value: '2038-01-19', expectValid: true },
    { name: 'year_1900', field: 'birthdate', value: '1900-01-01', expectValid: true },
    { name: 'year_2100', field: 'futureDate', value: '2100-12-31', expectValid: true },
    { name: 'invalid_date_feb30', field: 'date', value: '2024-02-30', expectValid: false },
    { name: 'invalid_date_month13', field: 'date', value: '2024-13-01', expectValid: false },

    // Special numeric formats
    { name: 'leading_zeros', field: 'code', value: '00123', expectValid: true },
    { name: 'scientific_notation', field: 'value', value: 1.23e10, expectValid: true },
    { name: 'hex_string', field: 'code', value: '0xFF', expectValid: true },
    { name: 'negative_string', field: 'amount', value: '-100', expectValid: false },

    // Whitespace boundaries
    { name: 'only_spaces', field: 'name', value: '   ', expectValid: false },
    { name: 'leading_spaces', field: 'name', value: '  John', expectValid: true },
    { name: 'trailing_spaces', field: 'name', value: 'John  ', expectValid: true },
    { name: 'tabs_only', field: 'name', value: '\t\t\t', expectValid: false },
    { name: 'newlines_only', field: 'name', value: '\n\n\n', expectValid: false },
  ];
}

export function isJsonTransportableBoundaryValue(value: any): boolean {
  if (value === undefined) return false;
  if (typeof value === 'number' && !Number.isFinite(value)) return false;
  return true;
}
