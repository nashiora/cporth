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
    PORTH_TK_WORD = 256,
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

typedef struct porth_program {
    porth_instructions instructions;
} porth_program;

void porth_vector_ensure_capacity(void** items, int64_t element_size, int64_t capacity, int64_t minimum_capacity);

porth_string_view porth_string_view_from_cstring(const char* cstring);

porth_arena* porth_arena_create(int64_t block_size);
void porth_arena_reset(porth_arena* arena);
void* porth_arena_push(porth_arena* arena, int64_t byte_count);
void porth_arena_destroy(porth_arena* arena);

porth_program* porth_compile(porth_source* source, porth_arena* arena);
void porth_program_destroy(porth_program* program);

#endif // !PORTH_H
