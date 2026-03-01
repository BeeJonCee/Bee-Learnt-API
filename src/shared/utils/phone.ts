export function normalizeSAPhone(value: string): string {
  const trimmed = value.trim();
  const digits = trimmed.replace(/\D/g, "");

  if (digits.startsWith("27") && digits.length === 11) {
    return `+${digits}`;
  }

  if (digits.startsWith("0") && digits.length === 10) {
    return `+27${digits.slice(1)}`;
  }

  return trimmed;
}

export function isE164Phone(value: string): boolean {
  return /^\+\d{7,15}$/.test(value);
}

export function maskPhone(phone: string): string {
  const visible = phone.slice(-2);
  return `${"*".repeat(Math.max(0, phone.length - 2))}${visible}`;
}
