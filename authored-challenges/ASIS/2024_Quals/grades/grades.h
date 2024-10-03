#ifndef HEADER_SPREADSHEET_H
#define HEADER_SPREADSHEET_H

#include <stdint.h>

typedef enum
{
	NUMBER = 0,
	STRING,
	CONDITIONAL
} CellType;

struct ConditionalExpression
{
	struct Cell *condition;
	uint64_t compare_value;
	uint64_t outcomes[2];
};

typedef struct Cell
{
	CellType type;
	union
	{
		uint64_t value;
		char *str;
		struct ConditionalExpression *cond_expr;
	};
} Cell;

#endif	// HEADER_SPREADSHEET_H
