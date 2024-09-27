/** Converts a base 32 string into a Uint8Array */
function base32ToUint8Array(base32: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(Math.floor((base32.length * 5) / 8));

  base32 = base32.toUpperCase().replace(/=+$/, "");

  for (const char of base32) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) throw new Error(`Invalid Base32 character "${char}"`);

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }

  return output;
}

/**
 * Generates the TOTP number using the provided base32 encoded token
 * 
 * @param token The token
 * @param options.timeStep The time step in seconds (default: 30)
 * @param options.timeOffset The time offset in seconds (default: 0)
 * @returns The current TOTP value such as `"321987"`
 */
export default async function getTotp(
  token: string,
  {
    timeStep = 30,
    timeOffset = 0,
  }: {
    timeStep?: number;
    timeOffset?: number;
  } = {}
): Promise<string> {
  const counterBuffer = new Uint8Array(8);
  const t = BigInt(
    Math.floor((Date.now() + timeOffset * 1000) / timeStep / 1000)
  );
  new DataView(counterBuffer.buffer).setBigInt64(0, t);

  const key = await window.crypto.subtle.importKey(
    "raw",
    base32ToUint8Array(token),
    { name: "HMAC", hash: "SHA-1" },
    true,
    ["sign", "verify"]
  );
  const hmac = await crypto.subtle.sign("HMAC", key, counterBuffer);
  const view = new DataView(hmac);
  const offset = view.getInt8(view.byteLength - 1) & 0x0f;
  const otpPart = view.getUint32(offset) & 0x7fffffff;
  const otp = otpPart % 10e5;
  return otp.toString().padStart(6, "0");
}
