#ifndef PORTH_H
#define PORTH_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define porth_vector(T) T*
#define porth_vector_push(V, E) do { porth_vector_ensure_capacity((void**)&(V)->items, sizeof *(V)->items, (V)->capacity, (V)->count + 1); (V)->items[(V)->count++] = (E); } while (0)
#define porth_vector_destroy(V) do { free((V)->items); (V)->items = NULL; (V)->count = 0; (V)->capacity = 0; } while (0)

typedef struct porth_string_view {
    const char* data;
    int64_t length;
} porth_string_view;

typedef struct porth_string_builder {
    char* items;
    int64_t count;
    int64_t capacity;
} porth_string_builder;

typedef struct porth_arena porth_arena;

typedef struct porth_source {
    porth_string_view full_name;
    porth_string_view text;
} porth_source;

typedef struct porth_location {
    porth_source* source;
    int64_t offset;
    int64_t length;
} porth_location;

typedef enum porth_token_kind {
    PORTH_TK_INVALID,
    PORTH_TK_EOF,
    PORTH_TK_INT,
    PORTH_TK_WORD,
    PORTH_TK_IF,
    PORTH_TK_IFSTAR,
    PORTH_TK_ELSE,
    PORTH_TK_END,
    PORTH_TK_WHILE,
    PORTH_TK_DO,
    PORTH_TK_INCLUDE,
    PORTH_TK_MEMORY,
    PORTH_TK_PROC,
    PORTH_TK_CONST,
    PORTH_TK_OFFSET,
    PORTH_TK_RESET,
    PORTH_TK_ASSERT,
    PORTH_TK_IN,
    PORTH_TK_BIKESHEDDER,
    PORTH_TK_INLINE,
    PORTH_TK_HERE,
    PORTH_TK_ADDR_OF,
    PORTH_TK_CALL_LIKE,
    PORTH_TK_LET,
    PORTH_TK_PEEK,
    PORTH_TK_STR,
    PORTH_TK_CSTR,
    PORTH_TK_CHAR,
} porth_token_kind;

typedef struct porth_token {
    porth_token_kind kind;
    porth_location location;

    union {
        int64_t integer_value;
        double float_value;
        porth_string_view string_value;
    };
} porth_token;

typedef enum porth_value_kind {
    PORTH_VALUE_INTEGER,
    PORTH_VALUE_FLOAT,
    PORTH_VALUE_STRING,
} porth_value_kind;

typedef struct porth_value {
    porth_value_kind kind;
    union {
        int64_t integer_value;
        double float_value;
        porth_string_view string_value;
    };
} porth_value;

typedef enum porth_datatype {
    PORTH_DATATYPE_INT,
    PORTH_DATATYPE_PTR,
    PORTH_DATATYPE_BOOL,
    PORTH_DATATYPE_ADDR,
} porth_datatype;

typedef struct porth_datatypes {
    porth_datatype* items;
    int64_t count;
    int64_t capacity;
} porth_datatypes;

typedef struct porth_named_constant {
    porth_string_view name;
    porth_value value;
} porth_named_constant;

typedef struct porth_named_constants {
    porth_named_constant* items;
    int64_t count;
    int64_t capacity;
} porth_named_constants;

typedef enum porth_instruction_kind {
    PORTH_INST_NOP,
} porth_instruction_kind;

typedef struct porth_instruction {
    porth_instruction_kind kind;
    union {
        int64_t operand;
        double float_operand;
    };
} porth_instruction;

typedef struct porth_instructions {
    porth_instruction* items;
    int64_t count;
    int64_t capacity;
} porth_instructions;

typedef struct porth_procedure {
    porth_string_view name;
    int64_t instruction_index;
    porth_datatypes input_stack;
    porth_datatypes output_stack;
} porth_procedure;

typedef struct porth_procedures {
    porth_procedure* items;
    int64_t count;
    int64_t capacity;
} porth_procedures;

typedef struct porth_program {
    porth_named_constants constants;
    porth_instructions instructions;
    porth_procedures procedures;
} porth_program;

void porth_vector_ensure_capacity(void** items, int64_t element_size, int64_t capacity, int64_t minimum_capacity);

porth_string_view porth_string_view_from_cstring(const char* cstring);
bool porth_string_view_equals(porth_string_view lhs, porth_string_view rhs);

porth_arena* porth_arena_create(int64_t block_size);
void porth_arena_reset(porth_arena* arena);
void* porth_arena_push(porth_arena* arena, int64_t byte_count);
void porth_arena_destroy(porth_arena* arena);

const char* porth_token_kind_to_cstring(porth_token_kind kind);

porth_program* porth_compile(porth_source* source, porth_arena* arena);
void porth_program_destroy(porth_program* program);

#endif // !PORTH_H
