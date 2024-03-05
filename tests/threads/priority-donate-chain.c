/* The main thread set its priority to PRI_MIN and creates 7 threads 
   (thread 1..7) with priorities PRI_MIN + 3, 6, 9, 12, ...
   The main thread initializes 8 locks: lock 0..7 and acquires lock 0.

   When thread[i] starts, it first acquires lock[i] (unless i == 7.)
   Subsequently, thread[i] attempts to acquire lock[i-1], which is held by
   thread[i-1], except for lock[0], which is held by the main thread.
   Because the lock is held, thread[i] donates its priority to thread[i-1],
   which donates to thread[i-2], and so on until the main thread
   receives the donation.

   After threads[1..7] have been created and are blocked on locks[0..7],
   the main thread releases lock[0], unblocking thread[1], and being
   preempted by it.
   Thread[1] then completes acquiring lock[0], then releases lock[0],
   then releases lock[1], unblocking thread[2], etc.
   Thread[7] finally acquires & releases lock[7] and exits, allowing 
   thread[6], then thread[5] etc. to run and exit until finally the 
   main thread exits.

   In addition, interloper threads are created at priority levels
   p = PRI_MIN + 2, 5, 8, 11, ... which should not be run until the 
   corresponding thread with priority p + 1 has finished.
  
   Written by Godmar Back <gback@cs.vt.edu> */ 

   /* 기본 스레드는 우선 순위를 PRI_MIN으로 설정하고 
   우선 순위 PRI_MIN + 3, 6, 9, 12, ...로 7개의 스레드(thread 1.7)를 생성합니다...
메인 스레드는 8개의 잠금: 잠금 0.7을 초기화하고 잠금 0을 획득합니다.

thread[i]가 시작되면 먼저 lock[i](i==7.이 아닌 한)을 획득합니다.
 이후 thread[i]는 메인 스레드에 의해 유지되는 lock[0]을 제외하고
  thread[i-1]에 의해 유지되는 lock[i-1]의 획득을 시도합니다. 
  잠금이 유지되기 때문에, 메인 스레드가 기부금을 받을 때까지 
  thread[i-1]는 자신의 우선 순위를 thread[i-1]에 기부합니다.

스레드[1..7]이 생성되어 잠금[0..7]에서 차단된 후, 
메인 스레드는 잠금[0]을 해제하고, 스레드[1]의 차단을 해제하고, 이에 의해 선점됩니다. 
그런 다음 스레드[1]는 잠금[0] 획득을 완료한 다음 
잠금[0]을 해제하고, 잠금[0]을 해제하고, 잠금[1]을 해제하고, 스레드[2]를 차단 해제합니다. 
스레드[7]은 최종적으로 잠금[7]과 종료를 획득하고 해제하여 스레드[6], 그리고 스레드[5] 등이 실행되고
 마지막으로 메인 스레드가 종료될 때까지 종료되도록 합니다.

또한 인터로퍼 스레드는 우선 순위 p = PRI_MIN + 2, 5, 8, 11, ...에서 생성되며 
우선 순위가 p + 1인 해당 스레드가 완료될 때까지 실행되어서는 안 됩니다.

고드마 백 지음 <gback@cs.vt.edu > */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

#define NESTING_DEPTH 8

struct lock_pair
  {
    struct lock *second;
    struct lock *first;
  };

static thread_func donor_thread_func;
static thread_func interloper_thread_func;

void
test_priority_donate_chain (void) 
{
  int i;  
  struct lock locks[NESTING_DEPTH - 1];
  struct lock_pair lock_pairs[NESTING_DEPTH];

  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  thread_set_priority (PRI_MIN);

  for (i = 0; i < NESTING_DEPTH - 1; i++)
    lock_init (&locks[i]);

  lock_acquire (&locks[0]);
  msg ("%s got lock.", thread_name ());

  for (i = 1; i < NESTING_DEPTH; i++)
    {
      char name[16];
      int thread_priority;

      snprintf (name, sizeof name, "thread %d", i);
      thread_priority = PRI_MIN + i * 3;
      lock_pairs[i].first = i < NESTING_DEPTH - 1 ? locks + i: NULL;
      lock_pairs[i].second = locks + i - 1;

      thread_create (name, thread_priority, donor_thread_func, lock_pairs + i);
      msg ("%s should have priority %d.  Actual priority: %d.",
          thread_name (), thread_priority, thread_get_priority ());

      snprintf (name, sizeof name, "interloper %d", i);
      thread_create (name, thread_priority - 1, interloper_thread_func, NULL);
    }

  lock_release (&locks[0]);
  msg ("%s finishing with priority %d.", thread_name (),
                                         thread_get_priority ());
}

static void
donor_thread_func (void *locks_) 
{
  struct lock_pair *locks = locks_;

  if (locks->first)
    lock_acquire (locks->first);

  lock_acquire (locks->second);
  msg ("%s got lock", thread_name ());

  lock_release (locks->second);
  msg ("%s should have priority %d. Actual priority: %d", 
        thread_name (), (NESTING_DEPTH - 1) * 3,
        thread_get_priority ());

  if (locks->first)
    lock_release (locks->first);

  msg ("%s finishing with priority %d.", thread_name (),
                                         thread_get_priority ());
}

static void
interloper_thread_func (void *arg_ UNUSED)
{
  msg ("%s finished.", thread_name ());
}

// vim: sw=2
