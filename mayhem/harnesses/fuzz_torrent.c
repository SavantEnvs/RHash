/*
 * librhash BitTorrent generation harness (rhash_torrent.h API + magnet printing).
 *
 * Input layout:
 *   [0]     torrent options (RHASH_TORRENT_OPT_*)
 *   [1..2]  piece length selector (0 = library default, else value * 1024)
 *   [3]     number of NUL-terminated strings that follow which are file paths (the remaining
 *           strings, up to the first empty one, are announce URLs). Each file path is followed by a
 *           1-byte size exponent used to derive its size.
 *   rest    the message hashed into the BTIH context.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "rhash.h"
#include "rhash_torrent.h"

static int initialized;

/* next NUL-terminated string in [*pos, size), or NULL if none */
static const char *next_str(const uint8_t *data, size_t size, size_t *pos)
{
	const uint8_t *nul;
	const char *s;
	if (*pos >= size)
		return NULL;
	nul = memchr(data + *pos, 0, size - *pos);
	if (!nul)
		return NULL;
	s = (const char *)data + *pos;
	*pos = (size_t)(nul - data) + 1;
	return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	rhash ctx;
	size_t pos = 4, piece;
	unsigned nfiles, i;
	const char *s;
	const char *first_name = NULL;
	char *magnet;
	size_t need;

	if (!initialized) {
		rhash_library_init();
		initialized = 1;
	}
	if (size < 4)
		return -1;
	ctx = rhash_init(RHASH_BTIH | RHASH_SHA1 | RHASH_ED2K | RHASH_AICH | RHASH_TTH);
	if (!ctx)
		return 0;
	rhash_torrent_set_options(ctx, data[0]);
	piece = ((size_t)data[1] | ((size_t)data[2] << 8)) * 1024;
	if (piece)
		rhash_torrent_set_piece_length(ctx, piece);
	nfiles = data[3] & 15;
	for (i = 0; i < nfiles; i++) {
		unsigned long long fsize;
		if (!(s = next_str(data, size, &pos)) || pos >= size)
			break;
		fsize = (unsigned long long)data[pos++] << 10;
		if (!first_name)
			first_name = s;
		rhash_torrent_add_file(ctx, s, fsize);
	}
	while ((s = next_str(data, size, &pos)) && *s)
		rhash_torrent_add_announce(ctx, s);
	if ((s = next_str(data, size, &pos)))
		rhash_torrent_set_program_name(ctx, s);
	if (pos < size)
		rhash_update(ctx, data + pos, size - pos);
	rhash_final(ctx, NULL);
	rhash_torrent_generate_content(ctx);

	need = rhash_print_magnet_multi(NULL, 0, first_name, ctx, RHPR_FILESIZE, 0, NULL);
	if (need > 0 && need < (1u << 20) && (magnet = malloc(need))) {
		rhash_print_magnet_multi(magnet, need, first_name, ctx, RHPR_FILESIZE, 0, NULL);
		free(magnet);
	}
	rhash_free(ctx);
	return 0;
}
