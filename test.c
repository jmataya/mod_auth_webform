#include <stdlib.h>
#include <string.h>

char * replace_substr(
        char *initial_str, 
        char *to_remove, 
        char *to_add) {
    int to_remove_index = 0;
    int to_add_index = 0;
    int main_index = 0;
    int new_index = 0;
    int placeholder_index = 0;
    int new_str_len = 0;
    char *new_str = NULL;
    
    // If to_remove is the same length or longer than to_add, then do everything
    // inline. Otherwise, allocate new space.
    new_str_len = strlen(initial_str) - strlen(to_remove) + strlen(to_add);
    if (strlen(initial_str) < new_str_len) {
        new_str = malloc(new_str_len * sizeof(char));
    }
    else {
        new_str = initial_str;
    }
    
    while (main_index < strlen(initial_str)) {
        
        // Set the placeholder index at the current spot.
        placeholder_index = main_index;
            
        while (to_remove_index < strlen(to_remove)) {
            new_str[new_index] = initial_str[main_index];
            if (initial_str[main_index] == to_remove[to_remove_index]) {
                new_index++;
                main_index++;
                to_remove_index++;
            }
            else {
                to_remove_index = 0;
                break;
            }
        }
        
        if (to_remove_index == strlen(to_remove)) {
            
            while (to_add_index < strlen(to_add) {
                
            }
        }
    }
    
    return new_str;
}

int main(int argc, char **argv) {
    return 0;
}
