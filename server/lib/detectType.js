const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const MD5_RE = /^[a-fA-F0-9]{32}$/;
const SHA1_RE = /^[a-fA-F0-9]{40}$/;
const SHA256_RE = /^[a-fA-F0-9]{64}$/;
const URL_RE = /^https?:\/\//i;
const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function detectIocType(raw) {
  const value = raw.trim();

  if (IPV4_RE.test(value)) {
    const octets = value.split('.').map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) {
      return { type: 'ip', value };
    }
  }
  if (IPV6_RE.test(value) && value.includes(':')) {
    return { type: 'ip', value };
  }
  if (URL_RE.test(value)) {
    return { type: 'url', value };
  }
  if (MD5_RE.test(value)) {
    return { type: 'hash', subtype: 'md5', value };
  }
  if (SHA1_RE.test(value)) {
    return { type: 'hash', subtype: 'sha1', value };
  }
  if (SHA256_RE.test(value)) {
    return { type: 'hash', subtype: 'sha256', value };
  }
  if (DOMAIN_RE.test(value)) {
    return { type: 'domain', value };
  }

  return { type: 'unknown', value };
}

export const PROVIDER_SUPPORT = {
  virustotal: ['ip', 'domain', 'url', 'hash'],
  abuseipdb: ['ip'],
  otx: ['ip', 'domain', 'url', 'hash'],
  proxycheck: ['ip'],       
  crowdsec: ['ip'],
};