#include "porth.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

porth_arena* temp_arena;

typedef struct porth_arena_block {
    void* memory;
    int64_t allocated;
} porth_arena_block;

typedef struct porth_arena_large_memory {
    void** items;
    int64_t count;
    int64_t capacity;
} porth_arena_large_memory;

struct porth_arena {
    int64_t block_size;
    int64_t block_index;

    porth_arena_block* items;
    int64_t count;
    int64_t capacity;

    porth_arena_large_memory large_memory;
};

typedef struct porth_parser {
    porth_arena* arena;
    porth_source* source;

    int64_t current_source_position;
    int current_character;
    int current_character_byte_count;

    porth_token token;
    porth_token next_token;
} porth_parser;

typedef struct porth_compile_state {
    porth_program* program;
    porth_datatypes type_stack;
    porth_instructions backpatch_stack;
} porth_compile_state;

int64_t porth_vector_ensure_capacity(void** items, int64_t element_size, int64_t capacity, int64_t minimum_capacity) {
    assert(items != NULL);
    assert(element_size > 0);
    assert(capacity >= 0);
    assert(minimum_capacity >= 0);

    if (capacity >= minimum_capacity) {
        return capacity; // already gucci
    }

    int64_t new_capacity = capacity;
    if (new_capacity == 0) {
        new_capacity = 16;
    } else {
        while (new_capacity < minimum_capacity) {
            new_capacity *= 2;
        }
    }

    *items = realloc(*items, (size_t)(new_capacity * element_size));
    memset(((char*)*items) + (capacity * element_size), 0, (new_capacity - capacity) * element_size);

    return new_capacity;
}

porth_string_view porth_string_view_from_cstring(const char* cstring) {
    return (porth_string_view){
        .data = cstring,
        .length = (int64_t)strlen(cstring),
    };
}

bool porth_string_view_equals(porth_string_view lhs, porth_string_view rhs) {
    return lhs.length == rhs.length && 0 == strncmp(lhs.data, rhs.data, (size_t)lhs.length);
}

void porth_string_builder_append(porth_string_builder* builder, const char* cstring) {
    int64_t cstring_length = (int64_t)strlen(cstring);
    builder->capacity = porth_vector_ensure_capacity(
        (void**)&builder->items,
        sizeof *builder->items,
        builder->capacity,
        builder->count + cstring_length + 1
    );
    memcpy(builder->items + builder->count, cstring, cstring_length + 1);
    builder->count += cstring_length;
}

porth_string_view porth_string_builder_as_view(porth_string_builder* builder) {
    char* data = porth_temp_alloc(builder->count + 1);
    memcpy(data, builder->items, builder->count + 1);
    return (porth_string_view){
        .data = data,
        .length = builder->count,
    };
}

void porth_string_builder_reset(porth_string_builder* builder) {
    porth_vector_reset(builder);
    memset(builder->items, 0, builder->capacity);
}

static porth_arena_block* porth_arena_get_block(porth_arena* arena, int64_t block_index) {
    while (block_index >= arena->count) {
        porth_arena_block block = {
            .memory = calloc(arena->block_size, 1),
            .allocated = 0,
        };

        porth_vector_push(arena, block);
    }

    return &arena->items[block_index];
}

porth_arena* porth_arena_create(int64_t block_size) {
    porth_arena* arena = calloc(1, sizeof *arena);
    arena->block_size = block_size;
    return arena;
}

void porth_arena_reset(porth_arena* arena) {
    arena->block_index = 0;
}

void* porth_arena_push(porth_arena* arena, int64_t byte_count) {
    // align to 8 bytes
    byte_count += (8 - (byte_count % 8)) % 8;

    if (byte_count > arena->block_size) {
        void* large_memory = calloc(byte_count, 1);
        porth_vector_push(&arena->large_memory, large_memory);
        return large_memory;
    }

    porth_arena_block* block = porth_arena_get_block(arena, arena->block_index);
    if ((arena->block_size - block->allocated) < byte_count) {
        arena->block_index++;
        block = porth_arena_get_block(arena, arena->block_index);
    }

    void* result = ((char*)block->memory) + block->allocated;
    block->allocated += byte_count;

    memset(result, 0, byte_count);
    return result;
}

void porth_arena_destroy(porth_arena* arena) {
    if (arena == NULL) return;

    for (int64_t i = 0; i < arena->large_memory.count; i++) {
        free(arena->large_memory.items[i]);
    }

    for (int64_t i = 0; i < arena->count; i++) {
        free(arena->items[i].memory);
    }

    porth_vector_destroy(&arena->large_memory);
    porth_vector_destroy(arena);

    free(arena);
}

void porth_temp_init() {
    assert(temp_arena == NULL && "cannot re-init temp allocator");
    temp_arena = porth_arena_create(16 * 1024);
}

void porth_temp_reset() {
    assert(temp_arena != NULL && "must first init temp allocator");
    porth_arena_reset(temp_arena);
}

void* porth_temp_alloc(int64_t count) {
    assert(temp_arena != NULL && "must first init temp allocator");
    return porth_arena_push(temp_arena, count);
}

void porth_temp_destroy() {
    if (temp_arena == NULL) return;
    porth_arena_destroy(temp_arena);
    temp_arena = NULL;
}

porth_string_view porth_temp_sprintf(const char* format, ...) {
    va_list v;
    va_start(v, format);
    porth_string_view result = porth_temp_vsprintf(format, v);
    va_end(v);
    return result;
}

porth_string_view porth_temp_vsprintf(const char* format, va_list v) {
    va_list v2;
    va_copy(v2, v);
    int64_t count = (int64_t)vsnprintf(NULL, 0, format, v2);
    va_end(v2);

    char* data = porth_temp_alloc(count + 1);
    vsnprintf(data, (size_t)count, format, v);
    data[count] = 0;

    return (porth_string_view){
        .data = data,
        .length = count
    };
}

void porth_diagnostic_push(porth_diagnostics* diagnostics, porth_diagnostic diagnostic) {
    porth_vector_push(diagnostics, diagnostic);
    if (diagnostic.kind >= PORTH_ERROR) {
        diagnostics->error_count++;
    }
}

void porth_diagnostics_report(porth_diagnostics* diagnostics) {
    for (int64_t i = 0; i < diagnostics->count; i++) {
        porth_diagnostic diagnostic = diagnostics->items[i];

        const char* color = "";
        const char* level = "LEVEL";

        switch (diagnostic.kind) {
            default: assert(false && "unreachable");
            case PORTH_TRACE: {
                color = ANSI_COLOR_WHITE;
                level = "Trace";
            } break;
            case PORTH_DEBUG: {
                color = ANSI_COLOR_GREEN;
                level = "Debug";
            } break;
            case PORTH_INFO: {
                color = ANSI_COLOR_CYAN;
                level = "Info";
            } break;
            case PORTH_WARNING: {
                color = ANSI_COLOR_YELLOW;
                level = "Warning";
            } break;
            case PORTH_ERROR: {
                color = ANSI_COLOR_RED;
                level = "Error";
            } break;
            case PORTH_FATAL: {
                color = ANSI_COLOR_MAGENTA;
                level = "Fatal";
            } break;
        }

        fprintf(
            stderr,
            "%s%.*s: %s%s[%ld]%s%s: %.*s%s\n",
            ANSI_STYLE_BOLD,
            (int)diagnostic.location.source->full_name.length,
            diagnostic.location.source->full_name.data,
            color,
            level,
            diagnostic.location.offset,
            ANSI_COLOR_RESET,
            ANSI_STYLE_BOLD,
            (int)diagnostic.message.length,
            diagnostic.message.data,
            ANSI_COLOR_RESET
        );
    }
}

const char* porth_token_kind_to_cstring(porth_token_kind kind) {
    switch (kind) {
        default: assert(false && "unreachable"); return "<unknown>";
        case PORTH_TK_INVALID: return "<invalid>";
        case PORTH_TK_EOF: return "<eof>";
        case PORTH_TK_INT: return "<int>";
        case PORTH_TK_WORD: return "<word>";
        case PORTH_TK_IF: return "if";
        case PORTH_TK_IFSTAR: return "if*";
        case PORTH_TK_ELSE: return "else";
        case PORTH_TK_END: return "end";
        case PORTH_TK_WHILE: return "while";
        case PORTH_TK_DO: return "do";
        case PORTH_TK_INCLUDE: return "include";
        case PORTH_TK_MEMORY: return "memory";
        case PORTH_TK_PROC: return "proc";
        case PORTH_TK_CONST: return "const";
        case PORTH_TK_OFFSET: return "offset";
        case PORTH_TK_RESET: return "reset";
        case PORTH_TK_ASSERT: return "assert";
        case PORTH_TK_IN: return "in";
        case PORTH_TK_BIKESHEDDER: return "--";
        case PORTH_TK_INLINE: return "inline";
        case PORTH_TK_HERE: return "here";
        case PORTH_TK_ADDR_OF: return "addr-of";
        case PORTH_TK_CALL_LIKE: return "call-like";
        case PORTH_TK_LET: return "let";
        case PORTH_TK_PEEK: return "peek";
        case PORTH_TK_STR: return "str";
        case PORTH_TK_CSTR: return "cstr";
        case PORTH_TK_CHAR: return "char";
    }
}

const char* porth_token_kind_to_human_string(porth_token_kind kind, bool plural) {
    switch (kind) {
        default: assert(false && "unreachable"); return "<unknown>";
        case PORTH_TK_INT: return plural ? "integers" : "an integer";
        case PORTH_TK_WORD: return plural ? "words" : "a word";
        case PORTH_TK_STR: return plural ? "strings" : "a string";
        case PORTH_TK_CSTR: return plural ? "C-style strings" : "a C-Style string";
        case PORTH_TK_CHAR: return plural ? "characters" : "a character";
    }
}

const char* porth_datatype_to_cstring(porth_datatype datatype) {
    switch (datatype) {
        default: assert(false && "unreachable"); return "<unknown>";
        case PORTH_DATATYPE_INT: return "int";
        case PORTH_DATATYPE_PTR: return "ptr";
        case PORTH_DATATYPE_BOOL: return "bool";
        case PORTH_DATATYPE_ADDR: return "addr";
    }
}

static struct {
    porth_intrinsic intrinsic;
    porth_string_view image;
} intrinsic_names[] = {
    {PORTH_INTRINSIC_PLUS, {"+", 1}},
    {PORTH_INTRINSIC_MINUS, {"-", 1}},
    {PORTH_INTRINSIC_MUL, {"*", 1}},
    {PORTH_INTRINSIC_DIVMOD, {"divmod", 6}},
    {PORTH_INTRINSIC_IDIVMOD, {"idivmod", 7}},
    {PORTH_INTRINSIC_MAX, {"max", 3}},
    {PORTH_INTRINSIC_PRINT, {"print", 5}},
    {PORTH_INTRINSIC_EQ, {"=", 1}},
    {PORTH_INTRINSIC_GT, {">", 1}},
    {PORTH_INTRINSIC_LT, {"<", 1}},
    {PORTH_INTRINSIC_GE, {">=", 2}},
    {PORTH_INTRINSIC_LE, {"<=", 2}},
    {PORTH_INTRINSIC_NE, {"!=", 2}},
    {PORTH_INTRINSIC_SHR, {"shr", 3}},
    {PORTH_INTRINSIC_SHL, {"shl", 3}},
    {PORTH_INTRINSIC_OR, {"or", 2}},
    {PORTH_INTRINSIC_AND, {"and", 3}},
    {PORTH_INTRINSIC_NOT, {"not", 3}},
    {PORTH_INTRINSIC_DUP, {"dup", 3}},
    {PORTH_INTRINSIC_SWAP, {"swap", 4}},
    {PORTH_INTRINSIC_DROP, {"drop", 4}},
    {PORTH_INTRINSIC_OVER, {"over", 4}},
    {PORTH_INTRINSIC_ROT, {"rot", 3}},
    {PORTH_INTRINSIC_STORE8, {"!8", 2}},
    {PORTH_INTRINSIC_LOAD8, {"@8", 2}},
    {PORTH_INTRINSIC_STORE16, {"!16", 3}},
    {PORTH_INTRINSIC_LOAD16, {"@16", 3}},
    {PORTH_INTRINSIC_STORE32, {"!32", 3}},
    {PORTH_INTRINSIC_LOAD32, {"@32", 3}},
    {PORTH_INTRINSIC_STORE64, {"!64", 3}},
    {PORTH_INTRINSIC_LOAD64, {"@64", 3}},
    {PORTH_INTRINSIC_CAST_PTR, {"cast(ptr)", 9}},
    {PORTH_INTRINSIC_CAST_INT, {"cast(int)", 9}},
    {PORTH_INTRINSIC_CAST_BOOL, {"cast(bool)", 10}},
    {PORTH_INTRINSIC_CAST_ADDR, {"cast(addr)", 10}},
    {PORTH_INTRINSIC_ARGC, {"argc", 4}},
    {PORTH_INTRINSIC_ARGV, {"argv", 4}},
    {PORTH_INTRINSIC_ENVP, {"envp", 4}},
    {PORTH_INTRINSIC_SYSCALL0, {"syscall0", 8}},
    {PORTH_INTRINSIC_SYSCALL1, {"syscall1", 8}},
    {PORTH_INTRINSIC_SYSCALL2, {"syscall2", 8}},
    {PORTH_INTRINSIC_SYSCALL3, {"syscall3", 8}},
    {PORTH_INTRINSIC_SYSCALL4, {"syscall4", 8}},
    {PORTH_INTRINSIC_SYSCALL5, {"syscall5", 8}},
    {PORTH_INTRINSIC_SYSCALL6, {"syscall6", 8}},
    {PORTH_INTRINSIC_QQQ, {"???", 3}},
    {0}
};

const char* porth_intrinsic_to_cstring(porth_intrinsic intrinsic) {
    switch (intrinsic) {
        default: assert(false && "unreachable"); return "<unknown>";
        case PORTH_INTRINSIC_PLUS: return "+";
        case PORTH_INTRINSIC_MINUS: return "-";
        case PORTH_INTRINSIC_MUL: return "*";
        case PORTH_INTRINSIC_DIVMOD: return "divmod";
        case PORTH_INTRINSIC_IDIVMOD: return "idivmod";
        case PORTH_INTRINSIC_MAX: return "max";
        case PORTH_INTRINSIC_PRINT: return "print";
        case PORTH_INTRINSIC_EQ: return "=";
        case PORTH_INTRINSIC_GT: return ">";
        case PORTH_INTRINSIC_LT: return "<";
        case PORTH_INTRINSIC_GE: return ">=";
        case PORTH_INTRINSIC_LE: return "<=";
        case PORTH_INTRINSIC_NE: return "!=";
        case PORTH_INTRINSIC_SHR: return "shr";
        case PORTH_INTRINSIC_SHL: return "shl";
        case PORTH_INTRINSIC_OR: return "or";
        case PORTH_INTRINSIC_AND: return "and";
        case PORTH_INTRINSIC_NOT: return "not";
        case PORTH_INTRINSIC_DUP: return "dup";
        case PORTH_INTRINSIC_SWAP: return "swap";
        case PORTH_INTRINSIC_DROP: return "drop";
        case PORTH_INTRINSIC_OVER: return "over";
        case PORTH_INTRINSIC_ROT: return "rot";
        case PORTH_INTRINSIC_STORE8: return "!8";
        case PORTH_INTRINSIC_LOAD8: return "@8";
        case PORTH_INTRINSIC_STORE16: return "!16";
        case PORTH_INTRINSIC_LOAD16: return "@16";
        case PORTH_INTRINSIC_STORE32: return "!32";
        case PORTH_INTRINSIC_LOAD32: return "@32";
        case PORTH_INTRINSIC_STORE64: return "!64";
        case PORTH_INTRINSIC_LOAD64: return "@64";
        case PORTH_INTRINSIC_CAST_PTR: return "cast(ptr)";
        case PORTH_INTRINSIC_CAST_INT: return "cast(int)";
        case PORTH_INTRINSIC_CAST_BOOL: return "cast(bool)";
        case PORTH_INTRINSIC_CAST_ADDR: return "cast(addr)";
        case PORTH_INTRINSIC_ARGC: return "argc";
        case PORTH_INTRINSIC_ARGV: return "argv";
        case PORTH_INTRINSIC_ENVP: return "envp";
        case PORTH_INTRINSIC_SYSCALL0: return "syscall0";
        case PORTH_INTRINSIC_SYSCALL1: return "syscall1";
        case PORTH_INTRINSIC_SYSCALL2: return "syscall2";
        case PORTH_INTRINSIC_SYSCALL3: return "syscall3";
        case PORTH_INTRINSIC_SYSCALL4: return "syscall4";
        case PORTH_INTRINSIC_SYSCALL5: return "syscall5";
        case PORTH_INTRINSIC_SYSCALL6: return "syscall6";
        case PORTH_INTRINSIC_QQQ: return "???";
    }
}

const char* porth_instruction_kind_to_cstring(porth_instruction_kind kind) {
    switch (kind) {
        default: assert(false && "unreachable"); return "<unknown>";
        case PORTH_INST_NOP: return "PORTH_INST_NOP";
        case PORTH_INST_PUSH_INT: return "PORTH_INST_PUSH_INT";
        case PORTH_INST_PUSH_BOOL: return "PORTH_INST_PUSH_BOOL";
        case PORTH_INST_PUSH_PTR: return "PORTH_INST_PUSH_PTR";
        case PORTH_INST_PUSH_ADDR: return "PORTH_INST_PUSH_ADDR";
        case PORTH_INST_PUSH_LOCAL_MEM: return "PORTH_INST_PUSH_LOCAL_MEM";
        case PORTH_INST_PUSH_GLOBAL_MEM: return "PORTH_INST_PUSH_GLOBAL_MEM";
        case PORTH_INST_PUSH_STR: return "PORTH_INST_PUSH_STR";
        case PORTH_INST_PUSH_CSTR: return "PORTH_INST_PUSH_CSTR";
        case PORTH_INST_IF: return "PORTH_INST_IF";
        case PORTH_INST_IFSTAR: return "PORTH_INST_IFSTAR";
        case PORTH_INST_ELSE: return "PORTH_INST_ELSE";
        case PORTH_INST_END_IF: return "PORTH_INST_END_IF";
        case PORTH_INST_END_WHILE: return "PORTH_INST_END_WHILE";
        case PORTH_INST_PREP_PROC: return "PORTH_INST_PREP_PROC";
        case PORTH_INST_RET: return "PORTH_INST_RET";
        case PORTH_INST_CALL: return "PORTH_INST_CALL";
        case PORTH_INST_INLINED: return "PORTH_INST_INLINED";
        case PORTH_INST_WHILE: return "PORTH_INST_WHILE";
        case PORTH_INST_DO: return "PORTH_INST_DO";
        case PORTH_INST_INTRINSIC: return "PORTH_INST_INTRINSIC";
        case PORTH_INST_CALL_LIKE: return "PORTH_INST_CALL_LIKE";
        case PORTH_INST_BIND_LET: return "PORTH_INST_BIND_LET";
        case PORTH_INST_BIND_PEEK: return "PORTH_INST_BIND_PEEK";
        case PORTH_INST_PUSH_BIND: return "PORTH_INST_PUSH_BIND";
        case PORTH_INST_UNBIND: return "PORTH_INST_UNBIND";
    }
}

void porth_push_instruction(porth_instructions* instructions, porth_instruction_kind kind, int64_t operand, porth_token token) {
    porth_instruction instruction = {
        .kind = kind,
        .operand = operand,
        .token = token,
    };
    porth_vector_push(instructions, instruction);
}

void porth_instructions_dump(porth_instructions* instructions) {
    for (int64_t i = 0; i < instructions->count; i++) {
        porth_instruction instruction = instructions->items[i];
        assert(instruction.token.location.source != NULL);

        porth_string_view source_name = instruction.token.location.source->full_name;
        fprintf(stdout, "%.*s[%ld]: %ld => %s ", (int)source_name.length, source_name.data, instruction.token.location.offset, i, porth_instruction_kind_to_cstring(instruction.kind));
        if (instruction.kind == PORTH_INST_INTRINSIC) {
            fprintf(stdout, "%s\n", porth_intrinsic_to_cstring((porth_intrinsic)instruction.operand));
        } else {
            fprintf(stdout, "%ld\n", instruction.operand);
        }
    }
}

static bool porth_parser_is_lexer_at_end(porth_parser* parser) {
    assert(parser != NULL);
    return parser->current_source_position >= parser->source->text.length;
}

static void porth_parser_next_character(porth_parser* parser) {
    assert(parser != NULL);

    if (porth_parser_is_lexer_at_end(parser)) {
        parser->current_character = 0;
        return;
    }

    parser->current_source_position += parser->current_character_byte_count;

    parser->current_character = parser->source->text.data[parser->current_source_position];
    parser->current_character_byte_count = 1;
}

static int porth_parser_peek_character(porth_parser* parser) {
    assert(parser != NULL);
    assert(parser->source != NULL);

    int64_t peek_position = parser->current_source_position + parser->current_character_byte_count;
    if (peek_position >= parser->source->text.length) {
        return 0;
    }

    return parser->source->text.data[peek_position];
}

static void porth_parser_skip_trivia(porth_parser* parser) {
    while (!porth_parser_is_lexer_at_end(parser)) {
        switch (parser->current_character) {
            default: return;

            case ' ':
            case '\t':
            case '\v':
            case '\r':
            case '\n': {
                porth_parser_next_character(parser);
            } break;

            case '/': {
                if (porth_parser_peek_character(parser) != '/') {
                    return;
                }

                while (!porth_parser_is_lexer_at_end(parser) && parser->current_character != '\n') {
                    porth_parser_next_character(parser);
                }
            } break;
        }
    }
}

static bool porth_is_digit(int character) {
    return character >= '0' && character <= '9';
}

static bool porth_is_word_boundary(int character) {
    return character == ' ' || character == '\t' || character == '\v' || character == '\r' || character == '\n' || character == 0;
}

static struct {
    porth_token_kind kind;
    porth_string_view image;
} keywords[] = {
    {PORTH_TK_IF, {"if", 2}},
    {PORTH_TK_IFSTAR, {"if*", 3}},
    {PORTH_TK_ELSE, {"else", 4}},
    {PORTH_TK_END, {"end", 3}},
    {PORTH_TK_WHILE, {"while", 5}},
    {PORTH_TK_DO, {"do", 2}},
    {PORTH_TK_INCLUDE, {"include", 7}},
    {PORTH_TK_MEMORY, {"memory", 6}},
    {PORTH_TK_PROC, {"proc", 4}},
    {PORTH_TK_CONST, {"const", 5}},
    {PORTH_TK_OFFSET, {"offset", 6}},
    {PORTH_TK_RESET, {"reset", 5}},
    {PORTH_TK_ASSERT, {"assert", 6}},
    {PORTH_TK_IN, {"in", 2}},
    {PORTH_TK_BIKESHEDDER, {"--", 2}},
    {PORTH_TK_INLINE, {"inline", 6}},
    {PORTH_TK_HERE, {"here", 4}},
    {PORTH_TK_ADDR_OF, {"addr-of", 7}},
    {PORTH_TK_CALL_LIKE, {"call-like", 9}},
    {PORTH_TK_LET, {"let", 3}},
    {PORTH_TK_PEEK, {"peek", 4}},
    {0}
};

static void porth_parser_read_next_token(porth_parser* parser, porth_token* token) {
    assert(parser != NULL);
    assert(parser->source != NULL);
    assert(token != NULL);

    porth_parser_skip_trivia(parser);
    int64_t start_position = parser->current_source_position;

    *token = (porth_token){
        .kind = PORTH_TK_INVALID,
        .location = {
            .source = parser->source,
            .offset = start_position,
            .length = 1,
        },
    };

    if (porth_parser_is_lexer_at_end(parser)) {
        token->kind = PORTH_TK_EOF;
        return;
    }

    // TODO(local): handle string literals early
    // TODO(local): track if this word is a number

    bool is_negative = false;

    if (parser->current_character == '"') {
        token->kind = PORTH_TK_STR;
        assert(false && "todo: lex string literals");
        goto done_lex;
    } else if (porth_is_digit(parser->current_character)) {
        token->kind = PORTH_TK_INT;
    } else if (parser->current_character == '-' && porth_is_digit(porth_parser_peek_character(parser))) {
        is_negative = true;
        token->kind = PORTH_TK_INT;
        porth_parser_next_character(parser);
    } else {
        token->kind = PORTH_TK_WORD;
    }

    while (!porth_parser_is_lexer_at_end(parser) && !porth_is_word_boundary(parser->current_character)) {
        int character = parser->current_character;
        porth_parser_next_character(parser);

        if (token->kind == PORTH_TK_INT) {
            if (porth_is_digit(character)) {
                token->integer_value = token->integer_value * 10 + (character - '0');
            } else {
                token->kind = PORTH_TK_WORD;
            }
        }
    }

done_lex:;
    token->location.length = parser->current_source_position - start_position;

    if (token->kind == PORTH_TK_INT) {
        if (is_negative) {
            token->integer_value *= -1;
        }
    } else if (token->kind == PORTH_TK_WORD) {
        token->string_value = (porth_string_view){
            .data = parser->source->text.data + start_position,
            .length = token->location.length,
        };

        for (int64_t i = 0; keywords[i].kind != 0; i++) {
            if (porth_string_view_equals(token->string_value, keywords[i].image)) {
                token->kind = keywords[i].kind;
                break;
            }
        }
    }

    assert(parser->current_source_position > start_position);
}

static void porth_expect_arity(porth_compile_state* state, porth_location location, int arity) {
    assert(state != NULL);

    if (state->type_stack.count < arity) {
        porth_diagnostic error = {
            .kind = PORTH_ERROR,
            .location = location,
            // TODO(local): gotta have a temp sprintf plz, or a wrapper around it
            .message = porth_temp_sprintf("Expected %d values on the stack, but only found %ld.", arity, state->type_stack.count),
        };
        porth_vector_push(&state->program->diagnostics, error);
    }

    for (int i = 0; i < arity && state->type_stack.count > 0; i++) {
        porth_discard porth_vector_pop(&state->type_stack);
    }
}

static void porth_expect_types(porth_compile_state* state, porth_location location, porth_datatype* datatypes, int count) {
    assert(state != NULL);

    bool correct = true;
    if (state->type_stack.count < count) {
        correct = false;
    }

    for (int i = 0; i < count && i < state->type_stack.count; i++) {
        porth_datatype stack_type = state->type_stack.items[state->type_stack.count - i - 1];
        porth_datatype expected_type = datatypes[count - i - 1];

        if (stack_type != expected_type) {
            correct = false;
        }
    }

    if (!correct) {
        porth_string_builder builder = {0};

        for (int i = 0; i < count; i++) {
            if (i > 0) porth_string_builder_append(&builder, ", ");
            porth_string_builder_append(&builder, porth_datatype_to_cstring(datatypes[i]));
        }
        porth_string_view expected_types = porth_string_builder_as_view(&builder);
        porth_vector_reset(&builder);

        for (int i = 0; i < count && i < state->type_stack.count; i++) {
            if (i > 0) porth_string_builder_append(&builder, ", ");
            porth_string_builder_append(
                &builder,
                porth_datatype_to_cstring(state->type_stack.items[state->type_stack.count - i - 1])
            );
        }
        porth_string_view found_types = porth_string_builder_as_view(&builder);
        porth_vector_destroy(&builder);

        porth_diagnostic error = {
            .kind = PORTH_ERROR,
            .location = location,
            // TODO(local): gotta have a temp sprintf plz, or a wrapper around it
            .message = porth_temp_sprintf(
                "Expected the stack to contain values of type (%.*s), but found (%.*s).\n",
                PORTH_SV_EXPAND(expected_types),
                PORTH_SV_EXPAND(found_types)
            ),
        };
        porth_vector_push(&state->program->diagnostics, error);
    }

    for (int i = 0; i < count && state->type_stack.count > 0; i++) {
        porth_discard porth_vector_pop(&state->type_stack);
    }
}

static void porth_compile_into(porth_compile_state* state, porth_source* source, porth_arena* arena) {
    assert(state != NULL);
    porth_program* program = state->program;
    assert(program != NULL);

    porth_parser parser = {
        .arena = arena,
        .source = source,
        .current_character = source->text.data[0],
        .current_character_byte_count = 1,
    };

    porth_parser_read_next_token(&parser, &parser.token);
    for (;;) {
        if (parser.token.kind == PORTH_TK_EOF) break;

#if 0
        if (parser.token.kind == PORTH_TK_INT) {
            fprintf(stderr, "INT : %ld\n", parser.token.integer_value);
        } else if (parser.token.kind == PORTH_TK_WORD) {
            fprintf(stderr, "WORD: %.*s\n", (int)parser.token.string_value.length, parser.token.string_value.data);
        } else {
            fprintf(stderr, "%s\n", porth_token_kind_to_cstring(parser.token.kind));
        }
#endif

        switch (parser.token.kind) {
            default: {
                fprintf(stderr, "unhandled token kind in porth_compile_into: %s\n", porth_token_kind_to_cstring(parser.token.kind));
                assert(false && "unhandled token kind in porth_compile_into");
            } break;

            case PORTH_TK_INT: {
                porth_push_instruction(&program->instructions, PORTH_INST_PUSH_INT, parser.token.integer_value, parser.token);
                porth_vector_push(&state->type_stack, PORTH_DATATYPE_INT);
                porth_parser_read_next_token(&parser, &parser.token);
            } break;

            case PORTH_TK_WORD: {
                porth_intrinsic intrinsic = PORTH_INTRINSIC_NONE;
                for (int64_t i = 0; intrinsic_names->intrinsic != PORTH_INTRINSIC_NONE; i++) {
                    if (porth_string_view_equals(parser.token.string_value, intrinsic_names[i].image)) {
                        intrinsic = intrinsic_names[i].intrinsic;
                        break;
                    }
                }

                if (intrinsic != PORTH_INTRINSIC_NONE) {
                    porth_push_instruction(&program->instructions, PORTH_INST_INTRINSIC, (int64_t)intrinsic, parser.token);
                    switch (intrinsic) {
                        default: {
                            fprintf(stderr, "for intrinsic %s\n", porth_intrinsic_to_cstring(intrinsic));
                            assert(false && "unimplemented intrinsic");
                        } break;

                        case PORTH_INTRINSIC_PLUS: {
                            porth_datatype expected[2] = {PORTH_DATATYPE_INT, PORTH_DATATYPE_INT};
                            porth_expect_types(state, parser.token.location, expected, 2);
                            porth_vector_push(&state->type_stack, PORTH_DATATYPE_INT);
                        } break;

                        case PORTH_INTRINSIC_PRINT: {
                            porth_expect_arity(state, parser.token.location, 1);
                        } break;
                    }
                } else {
                    assert(false && "todo user words");
                }

                porth_parser_read_next_token(&parser, &parser.token);
            } break;
        }
    }

    // TODO(local): program sanity checks
}

porth_program* porth_compile(porth_source* source, porth_arena* arena) {
    porth_program* program = calloc(1, sizeof *program);

    if (source == NULL || source->text.length == 0) {
        return program;
    }

    porth_compile_state state = {
        .program = program,
    };

    porth_compile_into(&state, source, arena);
    porth_vector_destroy(&state.type_stack);
    porth_vector_destroy(&state.backpatch_stack);

    return program;
}

void porth_program_destroy(porth_program* program) {
    if (program == NULL) return;

    porth_vector_destroy(&program->diagnostics);
    porth_vector_destroy(&program->procedures);
    porth_vector_destroy(&program->instructions);
    porth_vector_destroy(&program->global_memory);
    porth_vector_destroy(&program->constants);
    free(program);
}
