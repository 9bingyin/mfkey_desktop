#include "pixel_ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Animation arrays
const char* pixel_spinner[] = {"●○●", "○●○", "●○●", "○●○"};
const char* pixel_anim[] = {"▪▫▪", "▫▪▫", "▪▫▪", "▫▪▫"};
int animation_index = 0;

// Global UI options
static UIOptions ui_options = {false, true};

void pixel_ui_init(UIOptions* options) {
    if (options) {
        ui_options = *options;
    }
    
    // Check ANSI support
    if (!ui_options.no_ui && !pixel_ui_check_ansi_support()) {
        ui_options.no_ui = true;
        printf("Terminal doesn't support ANSI. Falling back to simple output.\n");
    }
}

bool pixel_ui_check_ansi_support(void) {
    // Simple check - can be improved
    char* term = getenv("TERM");
    if (!term) return false;
    
    // Check for common terminal types that support ANSI
    if (strstr(term, "xterm") || strstr(term, "color") || 
        strstr(term, "ansi") || strstr(term, "linux") ||
        strstr(term, "screen") || strstr(term, "tmux")) {
        return true;
    }
    
    return false;
}

void pixel_ui_show_title(void) {
    if (ui_options.no_ui) {
        printf("MIFARE Classic Key Recovery Tool\n");
        printf("================================================================================\n");
        return;
    }
    
    printf(CLEAR_SCREEN);
    
    if (ui_options.use_colors) printf(COLOR_CYAN COLOR_BOLD);
    printf("███╗   ███╗███████╗██╗  ██╗███████╗██╗   ██╗\n");
    printf("████╗ ████║██╔════╝██║ ██╔╝██╔════╝╚██╗ ██╔╝\n");
    printf("██╔████╔██║█████╗  █████╔╝ █████╗   ╚████╔╝ \n");
    printf("██║╚██╔╝██║██╔══╝  ██╔═██╗ ██╔══╝    ╚██╔╝  \n");
    printf("██║ ╚═╝ ██║██║     ██║  ██╗███████╗   ██║   \n");
    printf("╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   \n");
    if (ui_options.use_colors) printf(COLOR_RESET);
    
    printf("\n");
    
    if (ui_options.use_colors) printf(COLOR_MAGENTA);
    printf("░▒▓█ MIFARE Classic Key Recovery Tool █▓▒░\n");
    if (ui_options.use_colors) printf(COLOR_RESET);
    
    printf("════════════════════════════════════════════════════════════════\n\n");
}

void pixel_ui_show_config(const char* input_file, const char* output_file, const char* dict_dir) {
    if (ui_options.no_ui) {
        printf("Input file:  %s\n", input_file);
        printf("Output file: %s\n", output_file);
        if (dict_dir) printf("Dict output dir: %s\n", dict_dir);
        printf("================================================================================\n\n");
        return;
    }
    
    if (ui_options.use_colors) printf(COLOR_YELLOW);
    printf("▸ Input file:  %s\n", input_file);
    printf("▸ Output file: %s\n", output_file);
    if (dict_dir) {
        printf("▸ Dict dir:    %s\n", dict_dir);
    }
    if (ui_options.use_colors) printf(COLOR_RESET);
    printf("\n");
}

void pixel_ui_show_loading(const char* filename) {
    if (ui_options.no_ui) {
        printf("Loading nonces from %s...\n", filename);
        return;
    }
    
    printf("%s Loading nonces from %s...\n", pixel_anim[animation_index], filename);
    pixel_ui_update_animation();
}

void pixel_ui_show_nonce_loaded(int index, uint32_t uid, const char* attack_type) {
    if (ui_options.no_ui) {
        printf("Loaded nonce %d: UID=0x%08X, attack=%s\n", index, uid, attack_type);
        return;
    }
    
    printf("  └─ Loaded nonce %d: UID=0x%08X ", index, uid);
    if (ui_options.use_colors) {
        if (strcmp(attack_type, "static_encrypted") == 0) {
            printf(COLOR_YELLOW);
        } else {
            printf(COLOR_GREEN);
        }
    }
    printf("[%s]", attack_type);
    if (ui_options.use_colors) printf(COLOR_RESET);
    printf("\n");
}

void pixel_ui_show_loading_complete(int total_nonces) {
    if (ui_options.no_ui) {
        printf("Total nonces loaded: %d\n\n", total_nonces);
        return;
    }
    
    printf("  └─ Total nonces loaded: ");
    if (ui_options.use_colors) printf(COLOR_BOLD);
    printf("%d", total_nonces);
    if (ui_options.use_colors) printf(COLOR_RESET);
    printf("\n\n");
}

void pixel_ui_show_start(void) {
    if (ui_options.no_ui) {
        printf("Starting key recovery... (Press Ctrl+C to stop gracefully.)\n\n");
        return;
    }
    
    if (ui_options.use_colors) printf(COLOR_MAGENTA);
    printf("▓▒░ Starting key recovery... ");
    if (ui_options.use_colors) printf(COLOR_RESET);
    printf("(Press Ctrl+C to stop)\n");
    printf("────────────────────────────────────────────────────────────────\n");
}

// Static variable to track if progress needs to be redrawn
static bool progress_needs_redraw = false;

void pixel_ui_mark_progress_redraw(void) {
    progress_needs_redraw = true;
}

void pixel_ui_update_progress(int nonce_current, int nonce_total, 
                             int msb_current, int msb_total, 
                             float stage_progress, uint32_t current_uid) {
    if (ui_options.no_ui) {
        printf("\rProgress: Nonce %d/%d (%.1f%%) | MSB %d/%d (%.1f%%) | Current %.1f%%", 
               nonce_current, nonce_total, (float)nonce_current/nonce_total*100,
               msb_current, msb_total, (float)msb_current/msb_total*100,
               stage_progress);
        fflush(stdout);
        return;
    }
    
    // Use carriage return and ensure line is cleared
    printf("\r\033[K");  // Clear entire line
    
    // Build the complete line first
    char line[256];
    int len = 0;
    
    // Nonce info
    len += snprintf(line + len, sizeof(line) - len, "▸ Nonce %d/%d ", nonce_current, nonce_total);
    
    // Progress bars - use simpler format
    len += snprintf(line + len, sizeof(line) - len, "[");
    int n_filled = (nonce_current * 10) / nonce_total;
    for(int i = 0; i < 10; i++) {
        if (i < n_filled) {
            len += snprintf(line + len, sizeof(line) - len, "█");
        } else {
            len += snprintf(line + len, sizeof(line) - len, "░");
        }
    }
    len += snprintf(line + len, sizeof(line) - len, "] ");
    
    len += snprintf(line + len, sizeof(line) - len, "[");
    int m_filled = (msb_current * 10) / msb_total;
    for(int i = 0; i < 10; i++) {
        if (i < m_filled) {
            len += snprintf(line + len, sizeof(line) - len, "█");
        } else {
            len += snprintf(line + len, sizeof(line) - len, "░");
        }
    }
    len += snprintf(line + len, sizeof(line) - len, "] ");
    
    len += snprintf(line + len, sizeof(line) - len, "[");
    int s_filled = ((int)stage_progress * 10) / 100;
    for(int i = 0; i < 10; i++) {
        if (i < s_filled) {
            len += snprintf(line + len, sizeof(line) - len, "█");
        } else {
            len += snprintf(line + len, sizeof(line) - len, "░");
        }
    }
    len += snprintf(line + len, sizeof(line) - len, "] ");
    
    // UID
    len += snprintf(line + len, sizeof(line) - len, "0x%08X %s", current_uid, pixel_spinner[animation_index]);
    
    // Print the complete line
    printf("%s", line);
    
    pixel_ui_update_animation();
    fflush(stdout);
}

void pixel_ui_print_progress_bar(const char* label, int current, int total, int width) {
    float percentage = (float)current / total * 100;
    int filled = (int)(percentage / 100.0 * width);
    
    printf("%-6s ", label);
    
    for(int i = 0; i < width; i++) {
        if(i < filled) printf("█");
        else if(i == filled && percentage > (float)filled/width*100) printf("▓");
        else printf("░");
    }
    
    printf("  %3.0f%%  [%d/%d]", percentage, current, total);
}

void pixel_ui_show_found_key(const uint8_t* key_data, const char* attack_type) {
    if (ui_options.no_ui) {
        printf("\nFound key: ");
        for(int i = 0; i < 6; i++) {
            printf("%02X", key_data[i]);
        }
        printf("\n");
        return;
    }
    
    // Clear current line and print key
    printf("\r" CLEAR_LINE);
    if (ui_options.use_colors) printf(COLOR_GREEN);
    printf("✓ Found key: ");
    for(int i = 0; i < 6; i++) {
        printf("%02X", key_data[i]);
    }
    // Only show attack type if it's not empty
    if (attack_type && strlen(attack_type) > 0) {
        printf(" [%s]", attack_type);
    }
    if (ui_options.use_colors) printf(COLOR_RESET);
    printf("\n");
    fflush(stdout);
}

void pixel_ui_show_candidate_key(const uint8_t* key_data) {
    if (ui_options.no_ui) {
        return; // Don't show individual candidates in simple mode
    }
    
    // Clear current line and print candidate
    printf("\r" CLEAR_LINE);
    if (ui_options.use_colors) printf(COLOR_YELLOW);
    printf("? Found candidate: ");
    for(int i = 0; i < 6; i++) {
        printf("%02X", key_data[i]);
    }
    printf(" [static_encrypted - needs verification]");
    if (ui_options.use_colors) printf(COLOR_RESET);
    printf("\n");
    fflush(stdout);
}

void pixel_ui_show_summary(int total_nonces, int found_keys, int candidate_keys) {
    if (ui_options.no_ui) {
        printf("\n================================================================================\n");
        printf("Key recovery completed!\n\n");
        printf("Summary:\n");
        printf("Total nonces processed: %d\n", total_nonces);
        printf("Keys found: %d\n", found_keys);
        printf("Candidate keys: %d\n", candidate_keys);
        return;
    }
    
    // Clear progress line and move to new line
    printf("\r" CLEAR_LINE "\n");
    
    printf("════════════════════════════════════════════════════════════════\n");
    
    if (ui_options.use_colors) printf(COLOR_MAGENTA);
    printf("▓▒░ Key Recovery Complete! ░▒▓\n");
    if (ui_options.use_colors) printf(COLOR_RESET);
    
    printf("\nSummary:\n");
    printf("▸ Total nonces processed: %d\n", total_nonces);
    
    if (ui_options.use_colors) printf(COLOR_GREEN);
    printf("▸ Keys found: %d\n", found_keys);
    if (ui_options.use_colors) printf(COLOR_RESET);
    
    if (ui_options.use_colors) printf(COLOR_YELLOW);
    printf("▸ Candidate keys: %d\n", candidate_keys);
    if (ui_options.use_colors) printf(COLOR_RESET);
}

void pixel_ui_show_found_keys_list(const uint8_t keys[][6], int count) {
    if (count == 0) return;
    
    if (ui_options.no_ui) {
        printf("\nFound Keys:\n");
        for(int i = 0; i < count; i++) {
            printf("  ");
            for(int j = 0; j < 6; j++) {
                printf("%02X", keys[i][j]);
            }
            printf("\n");
        }
        return;
    }
    
    printf("\nFound Keys:\n");
    for(int i = 0; i < count; i++) {
        if (ui_options.use_colors) printf(COLOR_GREEN);
        printf("  ✓ ");
        for(int j = 0; j < 6; j++) {
            printf("%02X", keys[i][j]);
        }
        if (ui_options.use_colors) printf(COLOR_RESET);
        printf("\n");
    }
}

void pixel_ui_show_candidate_keys_summary(int count) {
    // Don't show anything here - we'll show in the saved files section
    (void)count; // Suppress unused parameter warning
    return;
}

void pixel_ui_show_saved_files(const char* keys_file, int keys_count, 
                              const char* dict_file, int candidates_count) {
    if (ui_options.no_ui) {
        // Non-GUI mode output
        if (candidates_count > 0 && dict_file) {
            printf("\nCandidate Keys (%d total):\n", candidates_count);
            const char* filename = strrchr(dict_file, '/');
            filename = filename ? filename + 1 : dict_file;
            printf("  Saved to: %s\n", filename);
            printf("  These keys need verification with actual card\n");
        }
        
        printf("\nFiles saved:\n");
        if (keys_count > 0) {
            printf("  %s (%d keys)\n", keys_file, keys_count);
        }
        if (candidates_count > 0 && dict_file) {
            printf("  %s (%d candidates)\n", dict_file, candidates_count);
        }
        return;
    }
    
    // GUI mode output
    if (candidates_count > 0 && dict_file) {
        printf("\nCandidate Keys (%d total):\n", candidates_count);
        if (ui_options.use_colors) printf(COLOR_YELLOW);
        // Extract just the filename from the full path
        const char* filename = strrchr(dict_file, '/');
        filename = filename ? filename + 1 : dict_file;
        printf("  ? Saved to: %s\n", filename);
        printf("  ? These keys need verification with actual card\n");
        if (ui_options.use_colors) printf(COLOR_RESET);
    }
    
    printf("\nFiles saved:\n");
    
    if (keys_count > 0) {
        if (ui_options.use_colors) printf(COLOR_GREEN);
        printf("  ▸ %s (%d keys)\n", keys_file, keys_count);
        if (ui_options.use_colors) printf(COLOR_RESET);
    }
    
    if (candidates_count > 0 && dict_file) {
        if (ui_options.use_colors) printf(COLOR_YELLOW);
        printf("  ▸ %s (%d candidates)\n", dict_file, candidates_count);
        if (ui_options.use_colors) printf(COLOR_RESET);
    }
}

void pixel_ui_show_no_keys_found(void) {
    if (ui_options.no_ui) {
        printf("No keys were recovered. This could happen if:\n");
        printf("  * The nonces are invalid or corrupted\n");
        printf("  * The keyspace being searched doesn't contain the key\n");
        printf("  * The attack was interrupted before completion\n\n");
        return;
    }
    
    if (ui_options.use_colors) printf(COLOR_RED);
    printf("\n✗ No keys were recovered.\n");
    if (ui_options.use_colors) printf(COLOR_RESET);
    
    printf("\nThis could happen if:\n");
    printf("  • The nonces are invalid or corrupted\n");
    printf("  • The keyspace being searched doesn't contain the key\n");
    printf("  • The attack was interrupted before completion\n\n");
}

void pixel_ui_update_animation(void) {
    animation_index = (animation_index + 1) % 4;
}

void pixel_ui_show_saved_dicts(const char* dict_files[], const int dict_counts[], int num_dicts) {
    if (num_dicts <= 0) return;

    if (ui_options.no_ui) {
        printf("\nCandidate dictionaries (%d files):\n", num_dicts);
        for (int i = 0; i < num_dicts; i++) {
            const char* file = dict_files[i] ? dict_files[i] : "";
            const char* filename = strrchr(file, '/');
            filename = filename ? filename + 1 : file;
            printf("  %s (%d candidates)\n", filename, dict_counts[i]);
        }
        return;
    }

    printf("\nCandidate dictionaries (%d files):\n", num_dicts);
    for (int i = 0; i < num_dicts; i++) {
        const char* file = dict_files[i] ? dict_files[i] : "";
        const char* filename = strrchr(file, '/');
        filename = filename ? filename + 1 : file;
        if (ui_options.use_colors) printf(COLOR_YELLOW);
        printf("  ▸ %s (%d candidates)\n", filename, dict_counts[i]);
        if (ui_options.use_colors) printf(COLOR_RESET);
    }
}
