/* FreeRTOSConfig.h for the POSIX port (Linux native), used by the op-sequence fuzzer. */
#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configUSE_PREEMPTION                    1
#define configUSE_IDLE_HOOK                     0
#define configUSE_TICK_HOOK                     0
#define configCPU_CLOCK_HZ                      ( ( unsigned long ) 100000000 )
#define configTICK_RATE_HZ                      ( ( TickType_t ) 1000 )
#define configMAX_PRIORITIES                    ( 10 )
#define configMINIMAL_STACK_SIZE                ( ( unsigned short ) 256 )
#define configTOTAL_HEAP_SIZE                   ( ( size_t ) ( 256 * 1024 ) )
#define configMAX_TASK_NAME_LEN                 ( 16 )
#ifndef configUSE_TRACE_FACILITY
#define configUSE_TRACE_FACILITY                0
#endif
#define configUSE_16_BIT_TICKS                  0
#define configIDLE_SHOULD_YIELD                 1
#define configUSE_MUTEXES                       1
#define configQUEUE_REGISTRY_SIZE               0
#define configCHECK_FOR_STACK_OVERFLOW          0
#define configUSE_RECURSIVE_MUTEXES             1
#define configUSE_MALLOC_FAILED_HOOK            1
#define configUSE_APPLICATION_TASK_TAG          0
#define configUSE_COUNTING_SEMAPHORES           1
#define configSUPPORT_STATIC_ALLOCATION         0
#define configSUPPORT_DYNAMIC_ALLOCATION        1

#define configUSE_CO_ROUTINES                   0
#define configMAX_CO_ROUTINE_PRIORITIES         ( 2 )

#define configUSE_TIMERS                        1
#define configTIMER_TASK_PRIORITY               ( configMAX_PRIORITIES - 1 )
#define configTIMER_QUEUE_LENGTH                10
#define configTIMER_TASK_STACK_DEPTH            ( configMINIMAL_STACK_SIZE * 2 )

#define INCLUDE_vTaskPrioritySet                1
#define INCLUDE_uxTaskPriorityGet               1
#define INCLUDE_vTaskDelete                     1
#define INCLUDE_vTaskCleanUpResources           1
#define INCLUDE_vTaskSuspend                    1
#define INCLUDE_vTaskDelayUntil                 1
#define INCLUDE_vTaskDelay                      1
#define INCLUDE_uxTaskGetStackHighWaterMark     0
#define INCLUDE_xTaskGetSchedulerState          1
#define INCLUDE_xTimerGetTimerDaemonTaskHandle  0
#define INCLUDE_xTaskGetIdleTaskHandle          0
#define INCLUDE_xTaskGetCurrentTaskHandle       1
#define INCLUDE_xSemaphoreGetMutexHolder        1
#define INCLUDE_eTaskGetState                   1
#define INCLUDE_xTaskAbortDelay                 1
#define INCLUDE_xTimerPendFunctionCall          1

/* Non-fatal: counts every failure in fr_kernel_asserts (fuzz_opseq.c) and
 * prints the first five per assert site. */
extern unsigned long fr_kernel_asserts;
#define configASSERT( x )    do { if( ( x ) == 0 ) { static int _asn=0; __sync_fetch_and_add( &fr_kernel_asserts, 1UL ); if(_asn++<5) { printf("ASSERT %s:%d\n", __FILE__, __LINE__); fflush(stdout); } } } while(0)
#define configTASK_NOTIFICATION_ARRAY_ENTRIES   3

#include <stdio.h>

#endif /* FREERTOS_CONFIG_H */
