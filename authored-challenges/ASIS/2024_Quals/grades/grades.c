#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "grades.h"

#define TABLE_SIZE 8
#define DISPLAY_WIDTH 6
#define NUMBER_DISPLAY_FORMAT "%-6lu"
#define STRING_DISPLAY_FORMAT "%-6s"

Cell table[TABLE_SIZE][TABLE_SIZE];

void clear_cell(int x, int y)
{
	if (table[x][y].type == STRING)
		free(table[x][y].str);
	else if (table[x][y].type == CONDITIONAL)
		free(table[x][y].cond_expr);
	table[x][y].type = NUMBER;
	table[x][y].value = 0;
}

void set_string(int x, int y, char *str)
{
	char *result = malloc(strlen(str) + 1);
	if (result == NULL)
	{
		puts("Error: out of memory");
		return;
	}

	clear_cell(x, y);
	table[x][y].type = STRING;
	table[x][y].str = result;

	while (*str != '"' && *str != '\0')
	{
		if (*str == '\\')
		{
			switch (str[1])
			{
				case 'n':
					*result++ = '\n';
					break;
				case 'r':
					*result++ = '\r';
					break;
				case 't':
					*result++ = '\t';
					break;
				default:
					*result++ = str[1];
			}
			str += 2;
		}
		else
		{
			*result++ = *str++;
		}
	}
}

void set_formula(int x, int y, char *str)
{
	int cond_x, cond_y;
	uint64_t cmp_value, outcomes[2];
	if (sscanf(str, "IF(%d:%d > %lu,%lu,%lu)", &cond_x, &cond_y, &cmp_value, outcomes, outcomes + 1) != 5)
	{
		puts("Error: bad input");
		return;
	}
	if (cond_x < 0 || cond_y < 0 || cond_x >= TABLE_SIZE || cond_y >= TABLE_SIZE)
	{
		puts("Error: bad input");
		return;
	}
	struct ConditionalExpression *expr = malloc(sizeof(struct ConditionalExpression));
	if (expr == NULL)
	{
		puts("Error: out of memory");
		return;
	}
	expr->condition = &table[cond_x][cond_y];
	expr->compare_value = cmp_value;
	expr->outcomes[0] = outcomes[0];
	expr->outcomes[1] = outcomes[1];

	clear_cell(x, y);
	table[x][y].type = CONDITIONAL;
	table[x][y].cond_expr = expr;
}

void set_number(int x, int y, char *str)
{
	uint64_t value = strtoul(str, NULL, 10);
	clear_cell(x, y);
	table[x][y].type = NUMBER;
	table[x][y].value = value;
}

void set_command(char *args)
{
	int x, y, value_index;
	if (sscanf(args, " %d %d %n", &x, &y, &value_index) != 2)
	{
		puts("Error: bad input");
		return;
	}
	if (x < 0 || y < 0 || x >= TABLE_SIZE || y >= TABLE_SIZE)
	{
		puts("Error: bad input");
		return;
	}
	if (args[value_index] == '"')
		set_string(x, y, args + value_index + 1);
	else if (args[value_index] == '=')
		set_formula(x, y, args + value_index + 1);
	else if (isdigit(args[value_index]))
		set_number(x, y, args + value_index);
	else
		puts("Error: bad input");
}

void display_string_cell(int x, int y)
{
	char *str = table[x][y].str;
	char disp[DISPLAY_WIDTH + 2] = {};
	if (strlen(str) > DISPLAY_WIDTH)
	{
		strncpy(disp, str, DISPLAY_WIDTH - 2);
		strcat(disp, "..");
		printf(STRING_DISPLAY_FORMAT, disp);
	}
	else
	{
		printf(STRING_DISPLAY_FORMAT, str);
	}
}

void display_formula(int x, int y)
{
	struct ConditionalExpression *expr = table[x][y].cond_expr;
	if (expr->condition->type != NUMBER)
	{
		printf(STRING_DISPLAY_FORMAT, "ERR");
		return;
	}
	printf(NUMBER_DISPLAY_FORMAT,
		(expr->condition->value > expr->compare_value) ? expr->outcomes[0] : expr->outcomes[1]);
}

void display(void)
{
	puts("Grades:");
	for (int i = 0; i < TABLE_SIZE; i++)
	{
		for (int j = 0; j < TABLE_SIZE; j++)
		{
			switch (table[i][j].type)
			{
				case NUMBER:
					printf(NUMBER_DISPLAY_FORMAT, table[i][j].value);
					break;
				case STRING:
					display_string_cell(i, j);
					break;
				case CONDITIONAL:
					display_formula(i, j);
					break;
			}
			putchar(' ');
		}
		putchar('\n');
	}
}

void parse_command(char *cmd)
{
	char op[16];
	if (sscanf(cmd, "%15s", op) != 1)
		return;
	if (strcmp(op, "set-grade") == 0)
		set_command(cmd + 9);
	else if (strcmp(op, "show-grades") == 0)
		display();
	else
		puts("Error: bad input");
}

void get_command(void)
{
	printf("> ");
	char command[1024];
	fgets(command, sizeof(command), stdin);
	command[strcspn(command, "\n")] = 0;
	parse_command(command);
}

void disable_io_buffering(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
}

int main(void)
{
	disable_io_buffering();
	while (true)
	{
		get_command();
	}
	return 0;
}
