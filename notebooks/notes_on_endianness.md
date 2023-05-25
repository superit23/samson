# Endianness in Samson
Alright, this is mostly a little reminder for me so I can implement endianness consistently. Any given cipher that operates on bytes can declare its endianness. `samson` works with many ciphers and thus must support big and little endianness.

Notes on endianness:
    - When we talk about hex in `samson` like `0x01020304`, we are talking about the BYTES REPRESENTATION
    - Python automatically converts these hex digits into an integer
    - Python is big endian. Putting `0x01020304` in the console will result in the big endian integer representation of those hex digits
    - The above statement is ALWAYS TRUE. So `int.to_bytes(0x01020304, 4, 'little')` is NOT the little endian representation of `0x01020304`. This can be seen when it comes out to `b'\x04\x03\x02\x01'`
    - `samson` provides a `Bytes` class to handle common byte operations
    - The correct way to handle the little endian representation of `0x01020304` is `Bytes(0x01020304).change_byteorder('little')`. This results in `<Bytes: b'\x01\x02\x03\x04', byteorder='little'>`
    - 
    - `samson` enforces endianness internally for each cipher
    - 