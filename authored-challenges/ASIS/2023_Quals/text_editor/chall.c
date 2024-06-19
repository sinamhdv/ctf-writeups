// gcc -Wall -o chall chall.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct {
	char text[256];
	char *error_message;
} text = {{}, "Invalid choice!\n"};

void setup(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

void print_menu(void)
{
	puts("Menu:");
	puts("1. edit text");
	puts("2. save text");
	puts("3. exit");
	printf("> ");
}

void edit_text(void)
{
	printf("Enter new text: ");
	read(0, &text, 264);
	puts("Done!");
}

void save_text(char *saved_text)
{
	memcpy(saved_text, &text, sizeof(text));
	puts("Saved the current text!");
}

void show_error(void)
{
	printf(text.error_message);
}

int main(void)
{
	setup();
	puts("Welcome to simple text editor!");
	char saved_text[256];
	while (1)
	{
		print_menu();
		int choice;
		scanf("%d", &choice);
		if (choice == 1)
			edit_text();
		else if (choice == 2)
			save_text(saved_text);
		else if (choice == 3)
			break;
		else
			show_error();
	}
	puts("Bye!");
	return 0;
}
