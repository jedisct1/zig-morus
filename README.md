# MORUS cipher for Zig

This is a Zig implementation of
[MORUS](https://competitions.cr.yp.to/round3/morusv2.pdf) (MORUS-1280-128)

MORUS is a fast authenticated cipher for platforms without hardware AES acceleration.

It performs especially well on WebAssembly compared to alternatives.

Its performance is comparable to AES-OCB, without using AES instructions.

Benchmark results on x86_64 (Macbook Pro, 2,4 GHz Core i9, single core):

```text
            morus:       5890 MiB/s
       aes128-ocb:       5824 MiB/s
```

Benchmark results for WebAssembly (WAVM)

```text
       aes128-gcm:        176 MiB/s
       aes128-ocb:        300 MiB/s
 xchacha8Poly1305:        319 MiB/s
       aegis-128l:        807 MiB/s
            rocca:        854 MiB/s
            morus:       3505 MiB/s
```

MORUS is the fastest cipher on Raspberry Pi 4, and possibly other ARM devices without crypto extensions:

```text
       aes128-gcm:         41 MiB/s
       aes128-ocb:         81 MiB/s
 xchacha8Poly1305:        159 MiB/s
       aegis-128l:        168 MiB/s
            rocca:        221 MiB/s
            morus:        713 MiB/s
```

On platforms with AES acceleration, [AEGIS](https://jedisct1.github.io/draft-aegis-aead/draft-irtf-cfrg-aegis-aead.html)(available in the standard library as `std.crypto.aead.aegis.Aegis128L`) and [ROCCA](https://github.com/jedisct1/zig-rocca) have higher performance.

Benchmark on Rocket Lake (Xeon E-2386G):

```text
       aes128-ocb:      10173 MiB/s
       aes256-ocb:       7792 MiB/s
            morus:      11069 MiB/s
            rocca:      16274 MiB/s
       aegis-128l:      21206 MiB/s (170 Gb/s)
```

Warning: MORUS doesn't provide 128-bit confidentiality even though [the best know attacks](https://eprint.iacr.org/2019/172.pdf) are impractical.
