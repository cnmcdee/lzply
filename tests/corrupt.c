/* corrupt.c - flip N bytes in a file at pseudo-random offsets.
 *
 * Usage: corrupt <file> <seed> <count> [start] [end]
 * Flips `count` distinct bytes in the range [start, end) by XORing
 * each with a random nonzero value. Prints the offsets flipped.
 * Used by the lzply test suite to prove BCH recovery and
 * failure behaviour. Deterministic for a given seed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t st;

static uint32_t rnd(void)
{
    st ^= st << 13;
    st ^= st >> 17;
    st ^= st << 5;
    return st;
}

int main(int argc, char **argv)
{
    const char *path;
    long seed, count;
    long start = 0, end = -1;
    FILE *f;
    long size, i;
    uint8_t *data;
    long *picked;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <file> <seed> <count> [start] [end]\n",
                argv[0]);
        return 1;
    }
    path = argv[1];
    seed = atol(argv[2]);
    count = atol(argv[3]);
    if (argc >= 5)
        start = atol(argv[4]);
    if (argc >= 6)
        end = atol(argv[5]);
    st = (uint32_t)(seed ? seed : 1);

    f = fopen(path, "r+b");
    if (!f) {
        perror("open");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    if (end < 0 || end > size)
        end = size;
    if (start < 0 || start >= end || count < 0 || count > end - start) {
        fprintf(stderr, "corrupt: bad range (start=%ld end=%ld count=%ld size=%ld)\n",
                start, end, count, size);
        fclose(f);
        return 1;
    }
    data = malloc((size_t)(end - start));
    if (!data) {
        fclose(f);
        return 1;
    }
    fseek(f, start, SEEK_SET);
    if (fread(data, 1, (size_t)(end - start), f) != (size_t)(end - start)) {
        fclose(f);
        free(data);
        return 1;
    }
    picked = malloc(sizeof(long) * (size_t)(count ? count : 1));
    for (i = 0; i < count; i++) {
        long pos;
        int dup;
        do {
            pos = start + (long)(rnd() % (uint32_t)(end - start));
            dup = 0;
            for (long q = 0; q < i; q++)
                if (picked[q] == pos)
                    dup = 1;
        } while (dup);
        picked[i] = pos;
        data[pos - start] ^= (uint8_t)(1 + (rnd() % 255));
        printf("%ld ", pos);
    }
    printf("\n");
    fseek(f, start, SEEK_SET);
    fwrite(data, 1, (size_t)(end - start), f);
    fclose(f);
    free(data);
    free(picked);
    return 0;
}
