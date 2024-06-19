#ifndef HEADER_CUSTOM_STRING
#define HEADER_CUSTOM_STRING

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
	size_t length;
	size_t capacity;
	char *data;
} String;

void String_init(String *str, size_t size)
{
	str->length = 0;
	str->capacity = size;
	str->data = malloc(size);
	if (str->data == 0) {
		puts("Error: malloc()");
		exit(1);
	}
}

void String_from_cstr(String *str, char *cstr)
{
	str->length = strlen(cstr);
	str->capacity = str->length + 1;
	str->data = malloc(str->capacity);
	if (str->data == 0) {
		puts("Error: malloc()");
		exit(1);
	}
	strcpy(str->data, cstr);
	str->data[str->length] = 0;
}

void String_push(String *str, char c)
{
	if (str->length == str->capacity) {	// XXX VULN: off-by-one
		char *newdata = malloc(2 * str->capacity);
		if (newdata == 0) {
			puts("Error: malloc()");
			exit(1);
		}
		memcpy(newdata, str->data, str->length);
		free(str->data);
		str->data = newdata;
		str->capacity *= 2;
	}
	str->data[str->length++] = c;
	str->data[str->length] = 0;	// single null-byte overflow
}

void String_pop(String *str)
{
	if (str->length <= 0)
		return;
	str->data[--str->length] = 0;
}

#endif	// HEADER_CUSTOM_STRING