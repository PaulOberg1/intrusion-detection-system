#include "hashset.h"

#include <stdio.h>

int size = SET_INITIAL_SIZE;

struct element {
    struct element *next;
    __uint32_t data;
};

//Appends element to linked list
void append_head(linkedlist *list, __uint32_t val) {
    struct element *elem = malloc(sizeof(struct element));
    elem -> data = val;
    elem -> next = NULL;
    if (list -> head == NULL) {
        list -> head = elem;
    }
    else {
        elem -> next = list -> head;
        list -> head = elem;
    }
}

//Checks if element is member of linked list
int check_member_list(linkedlist *list, __uint32_t val) {
    if (list -> head == NULL) {
        return 0;
    }
    struct element *elem = list -> head;
    while (elem != NULL) {
        if (elem -> data == val) {
            return 1;
        }
        elem = elem -> next;
    }
    return 0;
}

//Checks if element is a member of one of the linked lists in an array of linked lists (the set)
int check_member(set *s, __uint32_t val) {
    linkedlist **data = s->data;
    if (data[val % size] == NULL) {
        return 0;
    }
    return check_member_list(data[val % size], val);
}

//Adds an element to the array of linked lists
void add_array(linkedlist **data, __uint32_t val) {
    if (data[val % size] == NULL) {
        data[val % size] = calloc(1,sizeof(linkedlist));
    }
    append_head(data[val % size], val);
}

//Resizes the set if the load factor is exceeded
linkedlist **resize(linkedlist **data) {
    int i = 0;
    linkedlist **tmp = calloc(2*size, sizeof(linkedlist));
    for (i = 0; i < size; i++) {
        if (data[i] != NULL) {
            while (data[i]->head != NULL) {
                struct element *elem = data[i] -> head;
                add_array(tmp, elem->data);
                data[i]->head = elem->next;
                free(elem);
            }
            free(data[i]);
        }
    }
    free(data);
    size *= 2;
    return tmp;
}

//Adds an element to the set
void add(set *s, __uint32_t val) {
    if (s->count > 0.75*size) { //0.75 is load factor
        s->data = resize(s->data);
    }
    add_array(s->data, val);
    s->count++;
}