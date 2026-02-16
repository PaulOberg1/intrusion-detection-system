#include <stdlib.h>

#define SET_INITIAL_SIZE 1000

typedef struct linked_list {
    struct element *head;
} linkedlist;

typedef struct set {
    linkedlist **data;
    int count;
} set;

int check_member(set *s, __uint32_t val);

void add(set *s, __uint32_t val);