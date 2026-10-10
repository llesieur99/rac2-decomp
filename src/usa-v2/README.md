# USA v2.00 first trials

Exploratory C for the USA v2.00 target, checked with `scripts/try_function.py` against the
retail words of `baserom/SCUS_972.68` using the locally built GNU EE chain (`tools/linux/`).
The chain's source hashes equal the qualified ones (`docs/V2-SETUP.md`), but v2.00 has no campaign task,
no reservation and no register entry, so these add no credit.

| Function | Address | Size | Result |
| --- | --- | --- | --- |
| `IntToFloat` | `0x284690` | 16 | all 4 words equal |
| `HasMobyGroup` | `0x31B508` | 16 | all 4 words equal (`!= 0xFF`, not `^ 0xFF`) |
| `SetPopupItemEnabled` | `0x349368` | 16 | all 4 words equal (struct array member, not pointer arithmetic) |
| `FloatToInt` | `0x2846A0` | 16 | not matched: retail converts in place (`cvt.w.s $f12,$f12`); the chain always picks `$f0` for `(int)x` at -O1/-O2/-O3, so the original was probably handwritten |
