/* Ensures that a high-priority thread really preempts.

   Based on a test originally submitted for Stanford's CS 140 in
   winter 1999 by by Matt Franklin
   <startled@leland.stanford.edu>, Greg Hutchins
   <gmh@leland.stanford.edu>, Yu Ping Hu <yph@cs.stanford.edu>.
   Modified by arens. */

/* 우선 순위가 높은 스레드가 실제로 선점하는지 확인합니다.

원래 스탠퍼드의 CS 140을 위해 제출된 테스트를 기반으로 합니다
맷 프랭클린의 1999년 겨울
<startled@leland.stanford.edu >, 그렉 허친스
<gmh@leland.stanford.edu >, 위핑후 <yph@cs.stanford.edu >.
렌에 의해 수정되었습니다. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

static thread_func simple_thread_func;

void
test_priority_preempt (void) 
{
  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  /* Make sure our priority is the default. */
  ASSERT (thread_get_priority () == PRI_DEFAULT);

  thread_create ("high-priority", PRI_DEFAULT + 1, simple_thread_func, NULL);
  msg ("The high-priority thread should have already completed.");
}

static void 
simple_thread_func (void *aux UNUSED) 
{
  int i;
  
  for (i = 0; i < 5; i++) 
    {
      msg ("Thread %s iteration %d", thread_name (), i);
      thread_yield ();
    }
  msg ("Thread %s done!", thread_name ());
}
