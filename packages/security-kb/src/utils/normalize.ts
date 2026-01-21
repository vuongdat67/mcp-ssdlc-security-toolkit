/**
 * Data Normalization Utilities
 * 
 * Critical for SQLite data quality - ensures all values bound to prepared statements
 * are primitives (string, number, null), never objects or arrays.
 * 
 * Why this is needed:
 * - XML parsing often produces nested structures (objects with #text, attributes)
 * - SQLite bindings reject [object Object] and throw "Wrong API use" errors
 * - 285+ CWE records failed insertion due to object-typed fields
 */

/**
 * Normalizes any XML-derived value into a SQLite-safe string or null.
 * 
 * Handles:
 * - Nested objects with #text property (common in fast-xml-parser output)
 * - Arrays (joins with newlines for readability)
 * - Primitives (returns as-is after string conversion)
 * - null/undefined (returns null)
 * 
 * @param value - Raw value from XML parser
 * @returns SQLite-safe string or null
 */
export function normalizeForSQLite(value: any): string | null {
  // Handle null/undefined
  if (value === null || value === undefined) {
    return null;
  }

  // Handle primitive strings
  if (typeof value === 'string') {
    return value.trim() || null;
  }

  // Handle numbers/booleans
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  // Handle arrays - join with newlines for readability
  if (Array.isArray(value)) {
    const normalized = value
      .map(item => normalizeForSQLite(item))
      .filter(Boolean)
      .join('\n');
    return normalized || null;
  }

  // Handle objects with #text (fast-xml-parser structure)
  if (typeof value === 'object' && value !== null) {
    // Common pattern: { '#text': 'actual content', '@_attr': 'value' }
    if ('#text' in value) {
      return normalizeForSQLite(value['#text']);
    }

    // Try to extract meaningful text from nested structure
    // This handles cases like Extended_Description which may be deeply nested
    const textContent = extractTextFromObject(value);
    return textContent || null;
  }

  // Fallback - shouldn't reach here, but ensures safety
  return String(value);
}

/**
 * Recursively extracts text content from nested objects.
 * Used when #text is not at top level.
 */
function extractTextFromObject(obj: any): string | null {
  if (!obj || typeof obj !== 'object') {
    return null;
  }

  // Check common text fields
  if (obj.text) return String(obj.text).trim();
  if (obj.Text) return String(obj.Text).trim();
  if (obj.content) return String(obj.content).trim();
  if (obj.Content) return String(obj.Content).trim();

  // Recursively search for #text in nested structures
  for (const key in obj) {
    if (key === '#text' && typeof obj[key] === 'string') {
      return obj[key].trim();
    }
    if (typeof obj[key] === 'object') {
      const nested = extractTextFromObject(obj[key]);
      if (nested) return nested;
    }
  }

  // If no text found, try to stringify readable parts
  const entries = Object.entries(obj)
    .filter(([k, v]) => !k.startsWith('@_') && v !== null && v !== undefined)
    .map(([k, v]) => {
      if (typeof v === 'string') return v;
      if (typeof v === 'object') return extractTextFromObject(v);
      return String(v);
    })
    .filter(Boolean);

  return entries.length > 0 ? entries.join(' ').trim() : null;
}

/**
 * Normalizes JSON fields for SQLite storage.
 * 
 * Ensures arrays/objects are stored as JSON strings, not bound as objects.
 * Used for fields like mitigations_json, related_cwes_json.
 * 
 * @param value - Array or object to serialize
 * @returns JSON string or empty array '[]'
 */
export function normalizeJSONField(value: any): string {
  if (!value) {
    return '[]';
  }

  if (Array.isArray(value)) {
    return value.length > 0 ? JSON.stringify(value) : '[]';
  }

  if (typeof value === 'object') {
    return JSON.stringify(value);
  }

  // If already a string, assume it's valid JSON
  if (typeof value === 'string') {
    return value;
  }

  return '[]';
}

/**
 * Canonicalizes CWE identifiers to "CWE-<number>" format.
 * 
 * Why: Inconsistent IDs caused lookup failures (e.g., "79" vs "CWE-79").
 * 
 * Accepts:
 * - "79" → "CWE-79"
 * - "CWE-79" → "CWE-79"
 * - "cwe-79" → "CWE-79"
 * 
 * @param id - Raw CWE identifier
 * @returns Canonical "CWE-<number>" format
 */
export function canonicalizeCWEId(id: string | number | undefined): string | null {
  if (!id) return null;

  const idStr = String(id).trim().toUpperCase();
  
  // Already in correct format
  if (/^CWE-\d+$/.test(idStr)) {
    return idStr;
  }

  // Extract number from various formats
  const match = idStr.match(/(\d+)/);
  if (match) {
    return `CWE-${match[1]}`;
  }

  return null;
}

/**
 * Canonicalizes CVE identifiers to "CVE-YYYY-NNNNN" format.
 * 
 * Accepts:
 * - "CVE-2023-12345" → "CVE-2023-12345"
 * - "cve-2023-12345" → "CVE-2023-12345"
 * - "2023-12345" → "CVE-2023-12345"
 * 
 * @param id - Raw CVE identifier
 * @returns Canonical "CVE-YYYY-NNNNN" format
 */
export function canonicalizeCVEId(id: string | undefined): string | null {
  if (!id) return null;

  const idStr = String(id).trim().toUpperCase();

  // Already in correct format
  if (/^CVE-\d{4}-\d+$/.test(idStr)) {
    return idStr;
  }

  // Extract year and number
  const match = idStr.match(/(\d{4})-(\d+)/);
  if (match) {
    return `CVE-${match[1]}-${match[2]}`;
  }

  return null;
}

/**
 * Validates that a value is SQLite-safe (not an object or array).
 * Used in development/testing to catch binding issues early.
 * 
 * @param value - Value to validate
 * @param fieldName - Field name for error messages
 * @throws Error if value is not SQLite-safe
 */
export function assertSQLiteSafe(value: any, fieldName: string): void {
  if (value === null || value === undefined) {
    return; // null is safe
  }

  const type = typeof value;
  if (type === 'string' || type === 'number' || type === 'boolean') {
    return; // primitives are safe
  }

  if (Array.isArray(value)) {
    throw new Error(
      `Field "${fieldName}" contains array [${value.length} items]. Use normalizeJSONField() before binding.`
    );
  }

  if (type === 'object') {
    throw new Error(
      `Field "${fieldName}" contains object ${JSON.stringify(value)}. Use normalizeForSQLite() before binding.`
    );
  }
}
