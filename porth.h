#ifndef PORTH_H
#define PORTH_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define porth_vector(T) T*
#define porth_vector_push(V, E) do { (V)->capacity = porth_vector_ensure_capacity((void**)&(V)->items, sizeof *(V)->items, (V)->capacity, (V)->count + 1); (V)->items[(V)->count++] = (E); } while (0)
#define porth_vector_pop(V) ((V)->items[--(V)->count])
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

typedef enum porth_intrinsic {
    PORTH_INTRINSIC_NONE,
    PORTH_INTRINSIC_PLUS,
    PORTH_INTRINSIC_MINUS,
    PORTH_INTRINSIC_MUL,
    PORTH_INTRINSIC_DIVMOD,
    PORTH_INTRINSIC_IDIVMOD,
    PORTH_INTRINSIC_MAX,
    PORTH_INTRINSIC_EQ,
    PORTH_INTRINSIC_GT,
    PORTH_INTRINSIC_LT,
    PORTH_INTRINSIC_GE,
    PORTH_INTRINSIC_LE,
    PORTH_INTRINSIC_NE,
    PORTH_INTRINSIC_SHR,
    PORTH_INTRINSIC_SHL,
    PORTH_INTRINSIC_OR,
    PORTH_INTRINSIC_AND,
    PORTH_INTRINSIC_NOT,
    PORTH_INTRINSIC_PRINT,
    PORTH_INTRINSIC_DUP,
    PORTH_INTRINSIC_SWAP,
    PORTH_INTRINSIC_DROP,
    PORTH_INTRINSIC_OVER,
    PORTH_INTRINSIC_ROT,
    PORTH_INTRINSIC_LOAD8,
    PORTH_INTRINSIC_STORE8,
    PORTH_INTRINSIC_LOAD16,
    PORTH_INTRINSIC_STORE16,
    PORTH_INTRINSIC_LOAD32,
    PORTH_INTRINSIC_STORE32,
    PORTH_INTRINSIC_LOAD64,
    PORTH_INTRINSIC_STORE64,
    PORTH_INTRINSIC_CAST_PTR,
    PORTH_INTRINSIC_CAST_INT,
    PORTH_INTRINSIC_CAST_BOOL,
    PORTH_INTRINSIC_CAST_ADDR,
    PORTH_INTRINSIC_ARGC,
    PORTH_INTRINSIC_ARGV,
    PORTH_INTRINSIC_ENVP,
    PORTH_INTRINSIC_SYSCALL0,
    PORTH_INTRINSIC_SYSCALL1,
    PORTH_INTRINSIC_SYSCALL2,
    PORTH_INTRINSIC_SYSCALL3,
    PORTH_INTRINSIC_SYSCALL4,
    PORTH_INTRINSIC_SYSCALL5,
    PORTH_INTRINSIC_SYSCALL6,
    PORTH_INTRINSIC_QQQ,
} porth_intrinsic;

typedef enum porth_instruction_kind {
    PORTH_INST_NOP,
    PORTH_INST_PUSH_INT,
    PORTH_INST_PUSH_BOOL,
    PORTH_INST_PUSH_PTR,
    PORTH_INST_PUSH_ADDR,
    PORTH_INST_PUSH_LOCAL_MEM,
    PORTH_INST_PUSH_GLOBAL_MEM,
    PORTH_INST_PUSH_STR,
    PORTH_INST_PUSH_CSTR,
    PORTH_INST_IF,
    PORTH_INST_IFSTAR,
    PORTH_INST_ELSE,
    PORTH_INST_END_IF,
    PORTH_INST_END_WHILE,
    PORTH_INST_PREP_PROC,
    PORTH_INST_RET,
    PORTH_INST_CALL,
    PORTH_INST_INLINED,
    PORTH_INST_WHILE,
    PORTH_INST_DO,
    PORTH_INST_INTRINSIC,
    PORTH_INST_CALL_LIKE,
    PORTH_INST_BIND_LET,
    PORTH_INST_BIND_PEEK,
    PORTH_INST_PUSH_BIND,
    PORTH_INST_UNBIND,
} porth_instruction_kind;

typedef struct porth_instruction {
    porth_instruction_kind kind;
    porth_token token;
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

int64_t porth_vector_ensure_capacity(void** items, int64_t element_size, int64_t capacity, int64_t minimum_capacity);

porth_string_view porth_string_view_from_cstring(const char* cstring);
bool porth_string_view_equals(porth_string_view lhs, porth_string_view rhs);

porth_arena* porth_arena_create(int64_t block_size);
void porth_arena_reset(porth_arena* arena);
void* porth_arena_push(porth_arena* arena, int64_t byte_count);
void porth_arena_destroy(porth_arena* arena);

const char* porth_token_kind_to_cstring(porth_token_kind kind);
const char* porth_token_kind_to_human_string(porth_token_kind kind, bool plural);
const char* porth_datatype_to_cstring(porth_datatype datatype);
const char* porth_intrinsic_to_cstring(porth_intrinsic intrinsic);
const char* porth_instruction_kind_to_cstring(porth_instruction_kind kind);

void porth_instructions_push(porth_instructions* instructions, porth_instruction_kind kind, int64_t operand, porth_token token);
void porth_instructions_dump(porth_instructions* instructions);

porth_program* porth_compile(porth_source* source, porth_arena* arena);
void porth_program_destroy(porth_program* program);

#endif // !PORTH_H
