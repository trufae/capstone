/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#include <stdarg.h>
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#include <libkern/libkern.h>
#include <i386/limits.h>
#else
#include <stdio.h>
#include <limits.h>
#endif
#include <string.h>

#include <capstone/platform.h>

#include "SStream.h"
#include "cs_priv.h"
#include "utils.h"

#ifdef _MSC_VER
#pragma warning(disable: 4996) // disable MSVC's warning on strcpy()
#endif

void SStream_Init(SStream *ss)
{
	ss->index = 0;
	ss->buffer[0] = '\0';
}

void SStream_concat0(SStream *ss, const char *s)
{
#ifndef CAPSTONE_DIET
	unsigned int len = (unsigned int) strlen(s);

	SSTREAM_OVERFLOW_CHECK(ss, len);
	memcpy(ss->buffer + ss->index, s, len);
	ss->index += len;
	ss->buffer[ss->index] = '\0';
#endif
}

void SStream_concat1(SStream *ss, const char c)
{
#ifndef CAPSTONE_DIET
	SSTREAM_OVERFLOW_CHECK(ss, 1);
	ss->buffer[ss->index] = c;
	ss->index++;
	ss->buffer[ss->index] = '\0';
#endif
}

void SStream_concat(SStream *ss, const char *fmt, ...)
{
#ifndef CAPSTONE_DIET
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = cs_vsnprintf(ss->buffer + ss->index, sizeof(ss->buffer) - (ss->index + 1), fmt, ap);
	va_end(ap);
	if (ret < 0) {
		return;
	}
	SSTREAM_OVERFLOW_CHECK(ss, ret);
	ss->index += ret;
#endif
}

// Fast integer to hex string conversion, avoiding vsnprintf overhead.
// Returns number of characters written (not including null terminator).
static int fast_utoa_hex(char *buf, uint64_t val)
{
	static const char hex_chars[] = "0123456789abcdef";
	char tmp[17]; // max 16 hex digits + null
	int len = 0;

	if (val == 0) {
		buf[0] = '0';
		buf[1] = '\0';
		return 1;
	}

	// generate digits in reverse
	while (val) {
		tmp[len++] = hex_chars[val & 0xf];
		val >>= 4;
	}

	// reverse into output
	for (int i = 0; i < len; i++) {
		buf[i] = tmp[len - 1 - i];
	}
	buf[len] = '\0';
	return len;
}

// Fast unsigned integer to decimal string conversion.
static int fast_utoa_dec(char *buf, uint64_t val)
{
	char tmp[21]; // max 20 decimal digits + null
	int len = 0;

	if (val == 0) {
		buf[0] = '0';
		buf[1] = '\0';
		return 1;
	}

	while (val) {
		tmp[len++] = '0' + (char)(val % 10);
		val /= 10;
	}

	for (int i = 0; i < len; i++) {
		buf[i] = tmp[len - 1 - i];
	}
	buf[len] = '\0';
	return len;
}

// Fast SStream append for integer values with optional prefix/sign.
// This replaces SStream_concat(O, "prefix0x%x", val) patterns
// that were the #4 bottleneck due to vsnprintf overhead.
static void SStream_concat_num(SStream *ss, const char *prefix, uint64_t val, bool use_hex)
{
#ifndef CAPSTONE_DIET
	char *dst = ss->buffer + ss->index;
	char *end = ss->buffer + SSTREAM_BUF_LEN - 1;
	const char *p = prefix;
	int num_len;

	// copy prefix
	while (*p && dst < end) {
		*dst++ = *p++;
	}

	if (dst >= end) {
		*dst = '\0';
		ss->index = (int)(dst - ss->buffer);
		return;
	}

	if (use_hex) {
		num_len = fast_utoa_hex(dst, val);
	} else {
		num_len = fast_utoa_dec(dst, val);
	}

	dst += num_len;
	ss->index = (int)(dst - ss->buffer);
#endif
}

// print number with prefix #
void printInt64Bang(SStream *O, int64_t val)
{
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat_num(O, "#0x", (uint64_t)val, true);
		else
			SStream_concat_num(O, "#", (uint64_t)val, false);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == LONG_MIN)
				SStream_concat_num(O, "#-0x", (uint64_t)val, true);
			else
				SStream_concat_num(O, "#-0x", (uint64_t)-val, true);
		} else
			SStream_concat_num(O, "#-", (uint64_t)-val, false);
	}
}

void printUInt64Bang(SStream *O, uint64_t val)
{
	if (val > HEX_THRESHOLD)
		SStream_concat_num(O, "#0x", val, true);
	else
		SStream_concat_num(O, "#", val, false);
}

// print number
void printInt64(SStream *O, int64_t val)
{
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat_num(O, "0x", (uint64_t)val, true);
		else
			SStream_concat_num(O, "", (uint64_t)val, false);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == LONG_MIN)
				SStream_concat_num(O, "-0x", (uint64_t)val, true);
			else
				SStream_concat_num(O, "-0x", (uint64_t)-val, true);
		} else
			SStream_concat_num(O, "-", (uint64_t)-val, false);
	}
}

void printUInt64(SStream *O, uint64_t val)
{
	if (val > HEX_THRESHOLD)
		SStream_concat_num(O, "0x", val, true);
	else
		SStream_concat_num(O, "", val, false);
}

// print number in decimal mode
void printInt32BangDec(SStream *O, int32_t val)
{
	if (val >= 0)
		SStream_concat_num(O, "#", (uint64_t)(uint32_t)val, false);
	else {
		if (val == INT_MIN)
			SStream_concat_num(O, "#-", (uint64_t)(uint32_t)val, false);
		else
			SStream_concat_num(O, "#-", (uint64_t)(uint32_t)-val, false);
	}
}

void printInt32Bang(SStream *O, int32_t val)
{
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat_num(O, "#0x", (uint64_t)(uint32_t)val, true);
		else
			SStream_concat_num(O, "#", (uint64_t)(uint32_t)val, false);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == INT_MIN)
				SStream_concat_num(O, "#-0x", (uint64_t)(uint32_t)val, true);
			else
				SStream_concat_num(O, "#-0x", (uint64_t)(uint32_t)-val, true);
		} else
			SStream_concat_num(O, "#-", (uint64_t)(uint32_t)-val, false);
	}
}

void printInt32(SStream *O, int32_t val)
{
	if (val >= 0) {
		if (val > HEX_THRESHOLD)
			SStream_concat_num(O, "0x", (uint64_t)(uint32_t)val, true);
		else
			SStream_concat_num(O, "", (uint64_t)(uint32_t)val, false);
	} else {
		if (val <- HEX_THRESHOLD) {
			if (val == INT_MIN)
				SStream_concat_num(O, "-0x", (uint64_t)(uint32_t)val, true);
			else
				SStream_concat_num(O, "-0x", (uint64_t)(uint32_t)-val, true);
		} else
			SStream_concat_num(O, "-", (uint64_t)(uint32_t)-val, false);
	}
}

void printUInt32Bang(SStream *O, uint32_t val)
{
	if (val > HEX_THRESHOLD)
		SStream_concat_num(O, "#0x", (uint64_t)val, true);
	else
		SStream_concat_num(O, "#", (uint64_t)val, false);
}

void printUInt32(SStream *O, uint32_t val)
{
	if (val > HEX_THRESHOLD)
		SStream_concat_num(O, "0x", (uint64_t)val, true);
	else
		SStream_concat_num(O, "", (uint64_t)val, false);
}
