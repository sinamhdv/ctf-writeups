#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "custom_string.h"

#define MAX_BUFFERS 2
#define INIT_BUFFER_SIZE 24

String buffers[MAX_BUFFERS];
int tabs_count;
int current_tab;

void print_buffer(void)
{
	printf("Current buffer: %s\n", buffers[current_tab].data);
}

void type_characters(void)
{
	printf("Type characters: ");
	char buf[2048];
	int length = read(0, buf, sizeof(buf) - 1);
	if (length == -1) {
		puts("Error: read()");
		exit(1);
	}
	buf[length] = 0;
	for (int i = 0; i < length; i++) {
		String_push(&buffers[current_tab], buf[i]);
	}
	print_buffer();
	puts("Done!");
}

void backspace(void)
{
	printf("How many times? ");
	int cnt = -1;
	scanf("%d", &cnt);
	getchar();
	if (cnt <= 0 || cnt > 2000) {
		puts("Error: invalid count");
		return;
	}
	for (int i = 0; i < cnt; i++) {
		String_pop(&buffers[current_tab]);
	}
	print_buffer();
	puts("Done!");
}

void new_tab(void)
{
	if (tabs_count >= MAX_BUFFERS) {
		puts("Error: too many tabs");
		return;
	}
	printf("Paste content into new tab: ");
	char pasted_data[0x500];
	fgets(pasted_data, sizeof(pasted_data), stdin);
	String_from_cstr(&buffers[tabs_count++], pasted_data);
	current_tab = tabs_count - 1;
	print_buffer();
	puts("Done!");
}

void select_tab(void)
{
	printf("Enter tab index: ");
	int idx;
	scanf("%d", &idx);
	getchar();
	if (idx < 0 || idx >= tabs_count) {
		puts("Error: invalid index");
		return;
	}
	current_tab = idx;
	print_buffer();
	puts("Done!");
}

void print_menu(void)
{
	puts("Menu:");
	puts("======");
	puts("1. type characters");
	puts("2. backspace");
	puts("3. open new tab");
	puts("4. select tab");
	puts("5. exit");
	printf("> ");
}

void disable_io_buffering(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void init_editor(void)
{
	String_init(&buffers[0], INIT_BUFFER_SIZE);
	current_tab = 0;
	tabs_count = 1;
}

void setup(void)
{
	disable_io_buffering();
	init_editor();
}

int main(void)
{
	setup();
	puts("Welcome to my text editor!");
	while (1)
	{
		int choice = 0;
		print_menu();
		scanf("%d", &choice);
		getchar();
		switch (choice)
		{
			case 1:
				type_characters();
				break;
			case 2:
				backspace();
				break;
			case 3:
				new_tab();
				break;
			case 4:
				select_tab();
				break;
			case 5:
				exit(0);
				break;
			default:
				puts("Error: wrong choice");
				break;
		}
	}
	return 0;
}
