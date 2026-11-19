/*
 * librhash multi-hash update harness.
 *
 * Input layout:
 *   [0..3]  little-endian algorithm mask: bit i (0..30) selects hash id (1u << i), bit 31 selects
 *           BLAKE3; an all-zero mask selects every algorithm (RHASH_ALL_HASHES).
 *   [4]     print flags for rhash_print (format + modifiers).
 *   rest    a sequence of chunks: one length byte L, then up to L message bytes fed to
 *           rhash_update. L == 0 performs a zero-length update (the case fixed upstream in
 *           tiger.c, 9f53608b93), so the fuzzer controls the block alignment each algorithm sees.
 * After rhash_final every selected digest is printed in hex/base32/base64/raw plus a magnet link.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "rhash.h"

static int initialized;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned ids[32];
	size_t count = 0;
	uint32_t mask;
	int flags;
	rhash ctx;
	size_t pos, i;
	char out[1024];
	static const int formats[] = { RHPR_RAW, RHPR_HEX, RHPR_BASE32, RHPR_BASE64 };

	if (!initialized) {
		rhash_library_init();
		initialized = 1;
	}
	if (size < 5)
		return -1;
	mask = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
	flags = data[4];
	for (i = 0; i < 31; i++)
		if (mask & (1u << i))
			ids[count++] = 1u << i;
	if (mask & 0x80000000u)
		ids[count++] = RHASH_BLAKE3;
	if (count == 0) {
		ids[0] = RHASH_ALL_HASHES;
		count = 1;
	}
	ctx = rhash_init_multi(count, ids);
	if (!ctx)
		return 0;

	pos = 5;
	while (pos < size) {
		size_t len = data[pos++];
		if (len > size - pos)
			len = size - pos;
		rhash_update(ctx, data + pos, len);
		pos += len;
	}
	rhash_final(ctx, NULL);

	if (ids[0] == RHASH_ALL_HASHES) {
		count = 0;
		for (i = 0; i < 31; i++)
			ids[count++] = 1u << i;
		ids[count++] = RHASH_BLAKE3;
	}
	for (i = 0; i < count; i++) {
		size_t f;
		for (f = 0; f < 4; f++) {
			int pf = formats[f] | (flags & (RHPR_UPPERCASE | RHPR_REVERSE | RHPR_URLENCODE));
			size_t need = rhash_print(NULL, ctx, ids[i], pf);
			if (need > 0 && need < sizeof(out))
				rhash_print(out, ctx, ids[i], pf);
		}
	}
	{
		size_t need = rhash_print_magnet_multi(NULL, 0, "fuzz file name & co", ctx,
			flags & (RHPR_UPPERCASE | RHPR_NO_MAGNET | RHPR_FILESIZE), count, ids);
		if (need > 0 && need <= sizeof(out))
			rhash_print_magnet_multi(out, sizeof(out), "fuzz file name & co", ctx,
				flags & (RHPR_UPPERCASE | RHPR_NO_MAGNET | RHPR_FILESIZE), count, ids);
	}
	rhash_free(ctx);
	return 0;
}
