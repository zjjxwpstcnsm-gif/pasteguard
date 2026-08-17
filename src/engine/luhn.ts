export function passesLuhn(value: string): boolean {
  const digits = value.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) {
    return false;
  }

  let sum = 0;
  let doubleDigit = false;

  for (let index = digits.length - 1; index >= 0; index -= 1) {
    const character = digits[index];
    if (character === undefined) {
      return false;
    }

    let digit = Number(character);
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}
