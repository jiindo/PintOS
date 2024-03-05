/* The main thread acquires locks A and B, then it creates three
higher-priority threads.  The first two of these threads block
acquiring one of the locks and thus donate their priority to
the main thread.  The main thread releases the locks in turn
and relinquishes its donated priorities, allowing the third thread
to run.

In this test, the main thread releases the locks in a different
order compared to priority-donate-multiple.c.

Written by Godmar Back <gback@cs.vt.edu>. 
Based on a test originally submitted for Stanford's CS 140 in
winter 1999 by Matt Franklin <startled@leland.stanford.edu>,
Greg Hutchins <gmh@leland.stanford.edu>, Yu Ping Hu
<yph@cs.stanford.edu>.  Modified by arens. */

/* 메인 스레드는 잠금 A와 B를 획득한 다음, 우선 순위가 높은 세 개의 스레드를 생성합니다.
 이 중 처음 두 개의 스레드는 잠금 중 하나를 획득하는 것을 차단하여 우선 순위를 메인 스레드에 기부합니다. 
 메인 스레드는 잠금을 차례로 해제하고 기부된 우선 순위를 포기하여 세 번째 스레드를 실행할 수 있습니다.

이 테스트에서 메인 스레드는 priority-donate-multiple.c와 다른 순서로 잠금을 해제합니다.

Godmar Back <gback@cs.vt.edu > 지음.
Stanford의 CS 140을 위해 원래 제출된 테스트를 기반으로 합니다
Matt Franklin <startled@leland.stanford.edu >의 1999년 겨울,
Greg Hutchins <gmh@leland.stanford.edu >, Yu Ping Hu
<yph@cs.stanford.edu >. 렌에 의해 수정되었습니다. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

static thread_func a_thread_func;
static thread_func b_thread_func;
static thread_func c_thread_func;

void
test_priority_donate_multiple2 (void) 
{
  struct lock a, b;

  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  /* Make sure our priority is the default. */
  ASSERT (thread_get_priority () == PRI_DEFAULT);

  lock_init (&a);
  lock_init (&b);

  lock_acquire (&a);
  lock_acquire (&b);

  thread_create ("a", PRI_DEFAULT + 3, a_thread_func, &a);
  msg ("Main thread should have priority %d.  Actual priority: %d.",
       PRI_DEFAULT + 3, thread_get_priority ());

  thread_create ("c", PRI_DEFAULT + 1, c_thread_func, NULL);

  thread_create ("b", PRI_DEFAULT + 5, b_thread_func, &b);
  msg ("Main thread should have priority %d.  Actual priority: %d.",
       PRI_DEFAULT + 5, thread_get_priority ());

  lock_release (&a);
  msg ("Main thread should have priority %d.  Actual priority: %d.",
       PRI_DEFAULT + 5, thread_get_priority ());

  lock_release (&b);
  msg ("Threads b, a, c should have just finished, in that order.");
  msg ("Main thread should have priority %d.  Actual priority: %d.",
       PRI_DEFAULT, thread_get_priority ());
}

static void
a_thread_func (void *lock_) 
{
  struct lock *lock = lock_;

  lock_acquire (lock);
  msg ("Thread a acquired lock a.");
  lock_release (lock);
  msg ("Thread a finished.");
}

static void
b_thread_func (void *lock_) 
{
  struct lock *lock = lock_;

  lock_acquire (lock);
  msg ("Thread b acquired lock b.");
  lock_release (lock);
  msg ("Thread b finished.");
}

static void
c_thread_func (void *a_ UNUSED) 
{
  msg ("Thread c finished.");
}
