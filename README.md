# MORUS cipher for Zig

This is a Zig implementation of
[MORUS](https://competitions.cr.yp.to/round3/morusv2.pdf) (MORUS-1280-128)

MORUS is a fast authenticated cipher for platforms without hardware AES acceleration.

It performs especially well on WebAssembly compared to alternatives.

Benchmark results for WebAssembly (WAVM)

```text
       aes128-gcm:        176 MiB/s
       aes128-ocb:        300 MiB/s
 xchacha8Poly1305:        319 MiB/s
       aegis-128l:        807 MiB/s
            rocca:        854 MiB/s
            morus:       3505 MiB/s
```

On platforms with AES acceleration, [aegis](https://jedisct1.github.io/draft-aegis-aead/draft-denis-aegis-aead.html)(`std.crypto.aead.aegis.Aegis128L`) and [rocca](https://github.com/jedisct1/zig-rocca) remain a better choice.

Warning: MORUS doesn't provide 128-bit confidentiality even though [the best know attacks](https://eprint.iacr.org/2019/172.pdf) are impractical.
