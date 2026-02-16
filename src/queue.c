#include "queue.h"
#include <pcap.h>
#include <stdlib.h>

struct element {
    struct element *next;
    args *data;
};

int isEmpty(queue *queue) {
	return queue -> head == NULL;
}

void enqueue(queue *queue, args *val) {
    struct element *elem = malloc(sizeof(struct element));
    elem -> data = val;
    elem -> next = NULL;
    if (queue -> head == NULL) {
        queue -> head = elem;
		queue -> tail = elem;
    }
    else {
        queue -> tail -> next = elem;
		queue -> tail = elem;
    }
}

args *dequeue(queue *queue) {
    if (queue -> head != NULL) {
        struct element *elem = queue -> head;
        queue -> head = queue -> head -> next;
        args *ret = elem->data;
        free(elem);
        //Must free data after use in thread
		return ret;
    }
    return (args *) NULL;
}