/*
 * librhash context export/import harness.
 *
 * rhash_import() is a state-restore call: for every algorithm it copies the per-algorithm context
 * bytes of the blob into the new context (a plain memcpy, or a memcpy plus partial size checks for
 * the F_SPCEXP algorithms AICH/TTH/BTIH/BLAKE3) and trusts them. It is meant to read rhash_export()
 * output of the same build, so letting the fuzzer write those bytes only reports "the importer
 * trusts raw context state" again and again, once per algorithm. This harness therefore never lets
 * the input write context bytes. What it does let the input control is the part of the blob a
 * caller restoring a saved (possibly stale, truncated or edited) blob actually exposes:
 *
 *   [0..3]   little-endian algorithm mask (as in fuzz_hash_update.c): bit i (0..30) selects hash id
 *            (1u << i), bit 31 selects BLAKE3; an all-zero mask selects every algorithm.
 *   [4]      override bits: 1 = state, 2 = flags, 4 = msg_size, 8 = truncate the blob.
 *   [5..8]   export_header.state (little-endian), applied if override bit 1.
 *   [9..10]  export_header.flags, applied if override bit 2.
 *   [11..18] export_header.msg_size, applied if override bit 4.
 *   [19..20] number of bytes cut off the end of the blob, applied if override bit 8, taken modulo
 *            blob_size + 1 so every length from 0 to blob_size is reachable.
 *   [21]     split, rounded down to a multiple of 8: the first `split` message bytes are hashed
 *            before rhash_export.
 *   rest     message bytes; those not hashed before the export are hashed after the import.
 *
 * The blob is a real rhash_export() of rhash_init_multi + rhash_update, so every context is one
 * the library produced; hash_vector_size and the hash id list are never altered (they decide where
 * the context bytes sit). The (possibly truncated) blob is passed to rhash_import in an exactly
 * sized malloc'd buffer, so any read past its end is caught by ASan. The imported context is then
 * exported/imported once more, then updated, finalized and its digests printed. (No magnet link:
 * that is librhash-update's job, and its known rhash.c:777 overflow would fire on every seed.)
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "rhash.h"

#define HDR 22

static int initialized;

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* message bytes go through a malloc'd (aligned) copy: unaligned buffers trip edonr's misaligned
 * loads, which librhash-update already reports and which have nothing to do with import */
static void update_aligned(rhash ctx, const uint8_t *msg, size_t len)
{
	void *copy = malloc(len ? len : 1);
	if (!copy)
		return;
	memcpy(copy, msg, len);
	rhash_update(ctx, copy, len);
	free(copy);
}

static void use_context(rhash ctx, const uint8_t *msg, size_t len, size_t count, const unsigned *ids)
{
	char out[1024];
	size_t i, need;

	update_aligned(ctx, msg, len);
	rhash_final(ctx, NULL);
	for (i = 0; i < count; i++) {
		need = rhash_print(NULL, ctx, ids[i], RHPR_HEX);
		if (need > 0 && need < sizeof(out))
			rhash_print(out, ctx, ids[i], RHPR_HEX);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned ids[32];
	size_t count = 0, i, split, blob_size, cut;
	const uint8_t *msg;
	size_t msg_len;
	uint32_t mask;
	unsigned ov;
	uint8_t *blob, *in;
	rhash ctx, imp;

	if (!initialized) {
		rhash_library_init();
		initialized = 1;
	}
	if (size < HDR)
		return -1;
	mask = le32(data);
	ov = data[4];
	for (i = 0; i < 31; i++)
		if (mask & (1u << i))
			ids[count++] = 1u << i;
	if (mask & 0x80000000u)
		ids[count++] = RHASH_BLAKE3;
	if (count == 0) {
		for (i = 0; i < 31; i++)
			ids[count++] = 1u << i;
		ids[count++] = RHASH_BLAKE3;
	}
	msg = data + HDR;
	msg_len = size - HDR;
	/* a multiple of 8, so the post-import update stays 8-byte aligned after edonr fills its partial
	 * block (edonr reads blocks in place, misaligned or not, on x86: librhash-update's finding) */
	split = (size_t)(data[21] & ~7u);
	if (split > msg_len)
		split = msg_len & ~(size_t)7;

	ctx = rhash_init_multi(count, ids);
	if (!ctx)
		return 0;
	update_aligned(ctx, msg, split);
	blob_size = rhash_export(ctx, NULL, 0);
	if (blob_size < 16 || blob_size > (1u << 24) || !(blob = malloc(blob_size))) {
		rhash_free(ctx);
		return 0;
	}
	if (rhash_export(ctx, blob, blob_size) != blob_size) {
		free(blob);
		rhash_free(ctx);
		return 0;
	}
	rhash_free(ctx);

	/* export_header: uint32 state, uint16 hash_vector_size, uint16 flags, uint64 msg_size */
	if (ov & 1)
		memcpy(blob + 0, data + 5, 4);
	if (ov & 2)
		memcpy(blob + 6, data + 9, 2);
	if (ov & 4)
		memcpy(blob + 8, data + 11, 8);
	cut = 0;
	if (ov & 8) {
		cut = (size_t)data[19] | ((size_t)data[20] << 8);
		cut %= blob_size + 1;
	}
	/* never a zero-sized malloc: a 0-byte import still gets a (1-byte) buffer to read from */
	in = malloc(blob_size - cut ? blob_size - cut : 1);
	if (!in) {
		free(blob);
		return 0;
	}
	memcpy(in, blob, blob_size - cut);
	free(blob);
	imp = rhash_import(in, blob_size - cut);
	free(in);
	if (!imp)
		return 0;
	{
		/* round trip of the context as imported, before it is finalized */
		size_t need = rhash_export(imp, NULL, 0);
		if (need >= 16 && need < (1u << 24)) {
			void *exp = malloc(need);
			if (exp) {
				if (rhash_export(imp, exp, need) == need) {
					rhash again = rhash_import(exp, need);
					if (again)
						rhash_free(again);
				}
				free(exp);
			}
		}
	}
	use_context(imp, msg + split, msg_len - split, count, ids);
	rhash_free(imp);
	return 0;
}
