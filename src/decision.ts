/**
 * Interactive KDF Decision Tree — Panel 5
 */

export interface DecisionResult {
  kdf: 'HKDF' | 'Argon2id' | 'scrypt' | 'PBKDF2';
  reasoning: string;
  chip: string;
}

/**
 * 3-question decision tree:
 * 1. highEntropy: Is input high-entropy key material? (vs low-entropy password)
 * 2. multipleKeys: Do you need multiple independent keys from one root?
 * 3. legacy: Are you in a legacy / FIPS-constrained environment?
 */
export function decide(
  highEntropy: boolean,
  multipleKeys: boolean,
  legacy: boolean,
): DecisionResult {
  if (highEntropy) {
    return {
      kdf: 'HKDF',
      reasoning:
        'Your input already has high entropy. HKDF (RFC 5869) extracts then expands key material efficiently. ' +
        'It is used in TLS 1.3, Signal, and WireGuard. It is not suitable for passwords because it provides no ' +
        'intentional slowness.',
      chip: 'RECOMMENDED',
    };
  }
  // low-entropy (password)
  if (legacy) {
    return {
      kdf: 'PBKDF2',
      reasoning:
        'Your environment requires FIPS compliance or has no Argon2id support. PBKDF2 (RFC 8018) with HMAC-SHA-256 ' +
        'at 600,000+ iterations is the minimum acceptable choice per OWASP. Be aware that PBKDF2 is embarrassingly ' +
        'parallel; GPU and ASIC attacks are far cheaper than against memory-hard functions.',
      chip: 'ACCEPTABLE',
    };
  }
  if (multipleKeys) {
    return {
      kdf: 'Argon2id',
      reasoning:
        'For password-derived keys where you need multiple independent outputs, use Argon2id (RFC 9106) for the ' +
        'expensive derivation, then feed its output into HKDF-Expand with different info strings for domain ' +
        'separation. This gives you memory hardness and context binding.',
      chip: 'RECOMMENDED DEFAULT',
    };
  }
  return {
    kdf: 'Argon2id',
    reasoning:
      'Argon2id (RFC 9106) is the recommended default for new password storage and password-based key derivation. ' +
      'It combines data-dependent (Argon2d) and data-independent (Argon2i) memory access patterns, making it ' +
      'resistant to both side-channel attacks and GPU/ASIC brute-force. OWASP recommends t=2, m=19456 (19 MiB), p=1.',
    chip: 'RECOMMENDED DEFAULT',
  };
}

export const comparisonTable = [
  {
    kdf: 'HKDF',
    inputType: 'High-entropy key material',
    memoryHardness: 'None',
    gpuResistance: 'N/A (not for passwords)',
    fips: 'Yes (HMAC-based)',
    recommendedParams: 'SHA-256, salt, context info',
    status: 'RECOMMENDED (high-entropy)',
  },
  {
    kdf: 'PBKDF2',
    inputType: 'Passwords',
    memoryHardness: 'None',
    gpuResistance: 'Low — embarrassingly parallel',
    fips: 'Yes (SP 800-132)',
    recommendedParams: 'SHA-256, 600,000 iterations (OWASP)',
    status: 'ACCEPTABLE (legacy)',
  },
  {
    kdf: 'scrypt',
    inputType: 'Passwords',
    memoryHardness: 'Yes — sequential memory access',
    gpuResistance: 'High — memory-bound',
    fips: 'No',
    recommendedParams: 'N=2^17, r=8, p=1 (interactive)',
    status: 'RECOMMENDED (if no Argon2id)',
  },
  {
    kdf: 'Argon2id',
    inputType: 'Passwords',
    memoryHardness: 'Yes — data-dependent + independent',
    gpuResistance: 'Very high — memory + compute bound',
    fips: 'Not yet (RFC 9106)',
    recommendedParams: 't=2, m=19456 KB, p=1 (OWASP)',
    status: 'RECOMMENDED DEFAULT',
  },
];
