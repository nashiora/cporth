#include "porth.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

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

    porth_token token;
    porth_token next_token;
} porth_parser;

void porth_vector_ensure_capacity(void** items, int64_t element_size, int64_t capacity, int64_t minimum_capacity) {
    assert(items != NULL);
    assert(element_size > 0);
    assert(capacity >= 0);
    assert(minimum_capacity >= 0);

    if (capacity >= minimum_capacity) {
        return; // already gucci
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
}

porth_string_view porth_string_view_from_cstring(const char* cstring) {
    return (porth_string_view){
        .data = cstring,
        .length = (int64_t)strlen(cstring),
    };
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

    parser->current_source_position++;
    parser->current_character = parser->source->text.data[parser->current_source_position];
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
        }
    }
}

static bool porth_is_word_boundary(int character) {
    return character == ' ' || character == '\t' || character == '\v' || character == '\r' || character == '\n' || character == 0;
}

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

    while (!porth_parser_is_lexer_at_end(parser) && !porth_is_word_boundary(parser->current_character)) {
        porth_parser_next_character(parser);
    }

    token->kind = PORTH_TK_WORD;
    token->string_value = (porth_string_view){
        .data = parser->source->text.data + start_position,
        .length = parser->current_source_position - start_position,
    };

    assert(parser->current_source_position > start_position);
}

porth_program* porth_compile(porth_source* source, porth_arena* arena) {
    porth_program* program = calloc(1, sizeof *program);

    if (source == NULL || source->text.length == 0) {
        return program;
    }

    porth_parser parser = {
        .arena = arena,
        .source = source,
        .current_character = source->text.data[0],
    };

    while (1) {
        porth_parser_read_next_token(&parser, &parser.token);
        if (parser.token.kind == PORTH_TK_EOF) break;
        fprintf(stderr, "%.*s\n", (int)parser.token.string_value.length, parser.token.string_value.data);
    }

    return program;
}

void porth_program_destroy(porth_program* program) {
    if (program == NULL) return;

    porth_vector_destroy(&program->instructions);
    free(program);
}
