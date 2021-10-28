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
            morus:       2271 MiB/s
```

