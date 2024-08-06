#pragma once

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

const char *strchar(const char *str, int character) {
	char c = character;
	for (; *str != 0; ++str) {
		if (*str == c) {
			return str;
		}
	}
	return NULL;
}


void *memcopy(void *destination, const void *source, size_t num) {
	char *dest = destination;
	const char *src = source;
	for (size_t i = 0; i < num; ++i) {
		dest[i] = src[i];
	}
	return destination;
}


int memeq(const char *lhs, const char *rhs, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		if (lhs[i] != rhs[i]) {
			return FALSE;
		}
	}
	return TRUE;
}


int stringncmp(const char *lhs, const char *rhs, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		if (lhs[i] == 0) {
			return rhs[i] == 0 ? 0 : -1;
		} else {
			if (rhs[i] == 0) {
				return 1;
			} else {
				return lhs[i] < rhs[i] ? -1 : 1;
			}
		}
	}
	return 0;
}


int stringcmp(const char *lhs, const char *rhs) {
	return stringncmp(lhs, rhs, (size_t)-1);
}
