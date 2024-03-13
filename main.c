#include "porth.h"

#include <assert.h>
#include <stdio.h>

static porth_source* read_file(const char* file_path, porth_arena* arena);

static const char* args_shift(int* argc, char*** argv) {
    assert(argc != NULL);
    assert(argv != NULL);
    assert(*argc > 0);

    const char* result = (*argv)[0];
    (*argc)--;
    (*argv)++;
    return result;
}

typedef struct porthc_args {
    const char* program_name;
    bool help;
    bool version;
    bool verbose;

    const char* input_file;
} porthc_args;

static bool porthc_parse_args(porthc_args* args, int* argc, char*** argv);

int main(int argc, char** argv) {
    int exit_code = 0;

    porth_temp_init();

    porthc_args args = {0};
    if (!porthc_parse_args(&args, &argc, &argv)) {
        return 1;
    }

    porth_arena* arena = NULL;
    porth_source* source = NULL;
    porth_program* program = NULL;

    arena = porth_arena_create(16 * 1024 * 1024);
    
    source = read_file(args.input_file, arena);
    if (source == NULL) {
        exit_code = 1;
        goto exit_main;
    }

    program = porth_compile(source, arena);
    if (program == NULL) {
        exit_code = 1;
        goto exit_main;
    }

    porth_diagnostics_report(&program->diagnostics);
    //porth_instructions_dump(&program->instructions);

    if (program->diagnostics.error_count > 0) {
        exit_code = 1;
        goto exit_main;
    }

    porth_program_interpret(program);

exit_main:;
    porth_program_destroy(program);
    program = NULL;

    porth_arena_destroy(arena);
    arena = NULL;

    free(source);
    source = NULL;

    porth_temp_destroy();
    return exit_code;
}

static porth_source* read_file(const char* file_path, porth_arena* arena) {
    FILE* stream = fopen(file_path, "r");
    if (stream == NULL) {
        fprintf(stderr, "Could not open Porth source file '%s' for reading.\n", file_path);
        return NULL;
    }

    if (0 != fseek(stream, 0, SEEK_END)) {
        fprintf(stderr, "Could not seek to the end of the Porth source file '%s'.\n", file_path);
        fclose(stream);
        return NULL;
    }

    int64_t file_length = (int64_t)ftell(stream);
    if (file_length == 0) {
        porth_source* source = calloc(1, sizeof *source);
        source->full_name = porth_string_view_from_cstring(file_path);
        source->text = (porth_string_view){
            .data = NULL,
            .length = 0,
        };
        return source;
    }

    if (0 != fseek(stream, 0, SEEK_SET)) {
        fprintf(stderr, "Could not seek to the start of the Porth source file '%s'.\n", file_path);
        fclose(stream);
        return NULL;
    }

    char* file_contents = porth_arena_push(arena, file_length + 1);
    if (file_contents == NULL) {
        fprintf(stderr, "Could not allocate memory (%d B) to read Porth source file '%s' into. Buy more RAM, I guess.\n", (int)(file_length), file_path);
        fclose(stream);
        return NULL;
    }

    if (file_length != (int64_t)fread(file_contents, sizeof *file_contents, file_length, stream)) {
        fprintf(stderr, "Could not read all of Porth source file '%s' into memory.\n", file_path);
        fclose(stream);
        return NULL;
    }

    fclose(stream);

    porth_source* source = calloc(1, sizeof *source);
    source->full_name = porth_string_view_from_cstring(file_path);
    source->text = (porth_string_view){
        .data = file_contents,
        .length = file_length,
    };
    return source;
}

static bool porthc_parse_args(porthc_args* args, int* argc, char*** argv) {
    args->program_name = args_shift(argc, argv);
    while (*argc > 0) {
        const char* option = args_shift(argc, argv);
        if (0 == strcmp(option, "--help")) {
            args->help = true;
        } else if (0 == strcmp(option, "--version")) {
            args->version = true;
        } else if (0 == strcmp(option, "--verbose")) {
            args->verbose = true;
        } else {
            if (args->input_file != NULL) {
                fprintf(stderr, ANSI_STYLE_BOLD ANSI_COLOR_RED "Error" ANSI_COLOR_RESET ": Invalid option '%s'. If this is intended to be a source file, multiple input source files are not supported.\n", option);
                return false;
            }

            args->input_file = option;
        }
    }

    if (args->input_file == NULL) {
        fprintf(stderr, ANSI_STYLE_BOLD ANSI_COLOR_RED "Error" ANSI_COLOR_RESET ": No input source file provided.\n");
        return false;
    }
    
    return true;
}
