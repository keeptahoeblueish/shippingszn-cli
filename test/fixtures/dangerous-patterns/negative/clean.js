export function add(a, b) {
  return a + b;
}

export function matchDigits(text) {
  const re = /\d+/g;
  return re.exec(text);
}
