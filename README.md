# @md/totp

A function to generate TOTP values using a base64 encoded token

## Example

ts```
import getTotp from "@md/totp";

const token = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const totp = getTotp(token); // e.g. "431987"
```