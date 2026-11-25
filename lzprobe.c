/* lzprobe.c - minimal lzlib compress probe */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <lzlib.h>

int main(void)
{
    struct LZ_Encoder *enc;
    const char *msg = "hello world, hello lzip, hello world";
    uint8_t out[4096];
    int wr, rd, fin;
    enc = LZ_compress_open(1 << 23, 32, 0);
    printf("open: %p errno=%d (%s)\n", (void *)enc,
           enc ? (int)LZ_compress_errno(enc) : -1,
           enc ? LZ_strerror(LZ_compress_errno(enc)) : "n/a");
    if (!enc)
        return 1;
    printf("write_size=%d\n", LZ_compress_write_size(enc));
    wr = LZ_compress_write(enc, (const uint8_t *)msg, (int)strlen(msg));
    printf("write=%d errno=%d (%s)\n", wr, (int)LZ_compress_errno(enc),
           LZ_strerror(LZ_compress_errno(enc)));
    rd = LZ_compress_read(enc, out, sizeof out);
    printf("read=%d errno=%d (%s)\n", rd, (int)LZ_compress_errno(enc),
           LZ_strerror(LZ_compress_errno(enc)));
    fin = LZ_compress_finish(enc);
    printf("finish=%d errno=%d (%s)\n", fin, (int)LZ_compress_errno(enc),
           LZ_strerror(LZ_compress_errno(enc)));
    while (!LZ_compress_finished(enc)) {
        rd = LZ_compress_read(enc, out, sizeof out);
        printf("drain read=%d finished=%d errno=%d (%s)\n", rd,
               LZ_compress_finished(enc), (int)LZ_compress_errno(enc),
               LZ_strerror(LZ_compress_errno(enc)));
        if (rd <= 0)
            break;
    }
    printf("total_out=%llu\n",
           (unsigned long long)LZ_compress_total_out_size(enc));
    LZ_compress_close(enc);
    return 0;
}
