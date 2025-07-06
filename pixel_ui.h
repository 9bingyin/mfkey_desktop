#ifndef PIXEL_UI_H
#define PIXEL_UI_H

#include <stdbool.h>
#include <stdint.h>

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

// Clear screen and cursor control
#define CLEAR_SCREEN  "\033[2J\033[H"
#define CURSOR_UP(n)  "\033[" #n "A"
#define CURSOR_DOWN(n) "\033[" #n "B"
#define CURSOR_HOME   "\033[H"
#define CLEAR_LINE    "\033[K"

// Progress bar width
#define PROGRESS_BAR_WIDTH 30

// Animation characters
extern const char* pixel_spinner[];
extern const char* pixel_anim[];
extern int animation_index;

// UI Options
typedef struct {
    bool no_ui;        // Disable pixel UI
    bool use_colors;   // Enable color output
} UIOptions;

// Initialize pixel UI
void pixel_ui_init(UIOptions* options);

// Display ASCII art title
void pixel_ui_show_title(void);

// Display configuration info
void pixel_ui_show_config(const char* input_file, const char* output_file, const char* dict_dir);

// Display loading info
void pixel_ui_show_loading(const char* filename);

// Display loaded nonce info
void pixel_ui_show_nonce_loaded(int index, uint32_t uid, const char* attack_type);

// Display loading complete
void pixel_ui_show_loading_complete(int total_nonces);

// Display start message
void pixel_ui_show_start(void);

// Update progress display
void pixel_ui_update_progress(int nonce_current, int nonce_total, 
                             int msb_current, int msb_total, 
                             float stage_progress, uint32_t current_uid);

// Display found key
void pixel_ui_show_found_key(const uint8_t* key_data, const char* attack_type);

// Display candidate key
void pixel_ui_show_candidate_key(const uint8_t* key_data);

// Display completion summary
void pixel_ui_show_summary(int total_nonces, int found_keys, int candidate_keys);

// Display found keys list
void pixel_ui_show_found_keys_list(const uint8_t keys[][6], int count);

// Display candidate keys summary
void pixel_ui_show_candidate_keys_summary(int count);

// Display saved files info
void pixel_ui_show_saved_files(const char* keys_file, int keys_count, 
                               const char* dict_file, int candidates_count);

// Display no keys found message
void pixel_ui_show_no_keys_found(void);

// Update animation
void pixel_ui_update_animation(void);

// Helper function to print pixel-style progress bar
void pixel_ui_print_progress_bar(const char* label, int current, int total, int width);

// Check if terminal supports ANSI
bool pixel_ui_check_ansi_support(void);

// Mark that progress display needs redraw after key display
void pixel_ui_mark_progress_redraw(void);

#endif // PIXEL_UI_H