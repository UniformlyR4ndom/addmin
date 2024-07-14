#pragma once

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif



const char* std_strchr(const char* str, int character) {
	char c = character;
	while (*str) {
		if (*str == c) {
			return str;
		}
		++str;
	}
	return NULL;
}

void* std_memcpy(void* destination, const void* source, size_t num) {
	char* dest = destination;
	const char* src = source;
	for (size_t i = 0; i < num; ++i) {
		dest[i] = src[i];
	}
	return destination;
}


int memeq(const char* lhs, const char* rhs, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		if (lhs[i] != rhs[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

int strncmp(const char* lhs, const char* rhs, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		if (lhs[i] == 0) {
			if (rhs[i] == 0) {
				return 0;
			} else {
				return -1;
			}
		} else {
			if (rhs[i] == 0) {
				return 1;
			}
			if (lhs[i] < rhs[i]) {
				return -1;
			} else if (lhs[i] > rhs[i]) {
				return 1;
			}
		}
	}
	return 0;
}