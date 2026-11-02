/* fr_queue_shim.c -- wait-list introspection for the FreeRTOS adapter. It
 * compiles the kernel's queue.c through itself to see the private Queue_t, so
 * the Makefile builds this file instead of $(KERNEL)/queue.c. */
#include "queue.c"

#include "freertos_posix_adapter.h"

/* The i-th waiter on a mutex, in event-list order, or NULL. A take is a
 * receive, so takers wait on xTasksWaitingToReceive. */
void * frq_mutex_waiter_at(QueueHandle_t xMutex, int i)
{
    if (xMutex == NULL || i < 0) {
        return NULL;
    }

    Queue_t * const pxQueue = (Queue_t *) xMutex;
    const List_t * const pxList = &(pxQueue->xTasksWaitingToReceive);

    if ((UBaseType_t) i >= listCURRENT_LIST_LENGTH(pxList)) {
        return NULL;
    }

    const ListItem_t *pxItem = listGET_HEAD_ENTRY(pxList);
    for (int k = 0; k < i; k++) {
        pxItem = listGET_NEXT(pxItem);
    }
    return listGET_LIST_ITEM_OWNER(pxItem);
}

/* Snapshot the waiter list in one traversal: the number of TCBs written to
 * out[], or -1 if longer than cap. The caller holds the scheduler suspended. */
int frq_mutex_waiters_snapshot(QueueHandle_t xMutex, void **out, int cap)
{
    if (xMutex == NULL || out == NULL || cap < 0) {
        return 0;
    }

    Queue_t * const pxQueue = (Queue_t *) xMutex;
    const List_t * const pxList = &(pxQueue->xTasksWaitingToReceive);
    const UBaseType_t len = listCURRENT_LIST_LENGTH(pxList);

    if (len > (UBaseType_t) cap) {
        return -1;
    }

    const ListItem_t *pxItem = listGET_HEAD_ENTRY(pxList);
    for (UBaseType_t k = 0; k < len; k++) {
        out[k] = listGET_LIST_ITEM_OWNER(pxItem);
        pxItem = listGET_NEXT(pxItem);
    }
    return (int) len;
}

/* Number of tasks currently blocked taking this mutex. */
int frq_mutex_waiter_count(QueueHandle_t xMutex)
{
    if (xMutex == NULL) {
        return 0;
    }
    Queue_t * const pxQueue = (Queue_t *) xMutex;
    return (int) listCURRENT_LIST_LENGTH(&(pxQueue->xTasksWaitingToReceive));
}
