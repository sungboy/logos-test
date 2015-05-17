# 할일과 설명 #
## 가. timer\_sleep을 타이머 인터럽트를 사용하도록 변경 ##
<br>  1) timer.c, thread.c(특정함수에서 처리요?) 연관<br>
<br>  2) 기다리는 쓰레드 관리는 리스트로?<br>
<h2>나. 스케줄러 구현</h2>
<br>  1) 중요 키워드 : preemption, priority, 가변 Slice, Active/expired priority array, 우선순위 역전은 고려할 필요 없음<br>
<br>  2) thrad 관련 함수 목록을 보면서 특정 함수가 변경에서 누락되지 않도록 유의<br>
<br>  3) 비트맵 구현<br>
<br>   가) 구글에서 fls 검색 조교님 권장, 프로젝트 설명 자료 참고에도 뭔가 주소 있음<br>
<br>   나) 그러나 Pintos 것 사용이 더 좋을 듯?<br>
<br>   (단 이해해야, 프로젝트 설명의 구현방식 1, 2, 3 중 2, 3인지 확인해야)<br>
<br>   (문서에서 fixed size라고 하는데 문제 없을 듯...? )<br>
<h2>다. O(1) 스케줄러 (증명) 테스트셋 작성</h2>
<br>  1) 인터넷 검색을 통한 O(1) 스케줄러 (증명) 테스트셋 작성 기법 확인<br>
<br>  2) 해당 기법에 따른 테스트 셋 코드 작성<br>
<br>  3) 예상에 많은 스레드를 띄워서 테스트해야 할 듯?<br>
<h2>라. 문서화</h2>
<br>  1) 기본적으로 본인이 코딩한 부분은 본인이 작성<br>
<br>  2) 목차 및 각 목차 항목 별 분량, 필 포함 내용 논의 후 각자 작성, 취합<br>
<h1>업무 분장</h1>
조항준 - (나. 스케줄러 구현) - (비트맵)<br>
<br>박동민 - 가, 다 + 비트맵<br>
<br>문서화는 추후 논의 후 결정<br>
<h1>Pintos Bitmap 분석 결과 설명(박동민)</h1>
<h2>개요</h2>
<ul><li>Pintos의 Bitmap 코드는 lib/kernel/bitmap.c, lib/kernel/bitmap.h에 존재<br>
</li><li>프로젝트 설명 문서의 3가지 방법 중 2번으로 구현됨(일부 어셈블리 명령과 Generic Bit Operation 혼합)<br>
</li><li>프로젝트 설명 문서에는 set_bit(), clear_bit(), find_first_bit()의 기능을 하는 3가지 주요 함수가 구현되어야 한다고 되어 있고 Pintos 구현에서는 해당 기능을 수행하기 위해 각각 bitmap_mark, bitmap_reset, bitmap_scan 함수를 사용하면 됨<br>
<h2>전반적인 사용 흐름</h2>
</li><li>주의 - 비트맵 관련 함수들 중 일부는 원자적(atomic)이지 않다. 따라서 Interrupt Disable이 되지 않고 수행되는 코드 부분에서 여러 개의 스레드 또는 프로세스가 동시에 엑세스할 가능성이 있는 경우에는 Multi-thread Safe함을 동기화를 통해 보장하기 위해 Semaphore, Lock, Interrupt Disable 등 중 하나가 반드시 사용되어야 한다.<br>
</li><li>주의 - 아래 설명에 오타 등이 있을 수 있으니 코드가 원하는 대로 수행되지 않는 경우는 즉시 논의할 것<br>
<pre><code>//생성<br>
struct bitmap* bm = bitmap_create( (할당할 비트 수) ); // 할당 후 모든 비트는 0으로 초기화됨<br>
</code></pre>
<pre><code>//값 변경<br>
//// 특정 비트를 0으로 변경<br>
bitmap_reset(bm, (비트 인덱스(예를 들어 0이면 첫번째 비트, 1이면 두번째 비트 등)) );<br>
//// 특정 비트를 1로 변경<br>
bitmap_mark(bm, (비트 인덱스)) );<br>
//// 기타 여러 비트 변경 등의 함수가 있으나 불필요할 듯하여 생략함<br>
//// 필요 시 추가요구 바람<br>
</code></pre>
<pre><code>//가장 먼저 1로 설정된 비트 알아내기<br>
//bitmap_scan함수를 이용한다. bitmap_scan은 1이 나오는 첫번째 비트 찾기 이외에 <br>
//연속한 여러 비트가 0이거나 1인 경우를 찾는 기능이 수행될 수 있으나 <br>
//필요하지 않을 듯 하여 설명하지 않음. 해당 기능 필요시 요구 바람<br>
//주의 - bitmap_scan 함수를 통해서는 1로 설정된 여러 비트 중 가장 인덱스가 낮은 비트만 찾을 수 있다. <br>
//(즉 예를 들어 비트0(가장 처음 비트)과 비트 10만 1인 경우는 0이 리턴되어 10을 알 수는 없다.)<br>
// 따라서 우선순위가 가장 높은 경우를 비트0에, 우선순위가 2번째로 가장 높은 경우를 비트 1로 등과 같이 사용해야 bitmap_scan 함수를 통해서 <br>
//스레드가 존재하는 가장 높은 우선순위의 큐를 찾을 수 있다. <br>
idx = bitmap_scan(bm, 0, 1, true); //idx가 찾은 큐의 인덱스<br>
</code></pre>
<pre><code>//해제<br>
bitmap_destroy(bm);<br>
</code></pre></li></ul>

<h1>박동민 조항준 코드 1차 동료검토(2009/10/12)</h1>
<ul><li>주석 스타일이 좀 다른 듯?<br>
</li><li>alarm-multiple은 내가 작성한 것 반영해서?<br>
</li><li>수정 함수 주석도 맞는지 확인해야 할 듯?<br>
<h2>작성 코드 검토(thread.c)</h2>
- 55 줄 -> 삭제?<br>
<br>   - 56 줄 -> 삭제?<br>
<br>   - 58 줄 -> 고정 버퍼로...<br>
<br>   - 60 줄 -> PRI_MAX-PRI_MIN+1 등으로?<br>
<br>   - 116~117 줄 -> 삭제?<br>
<br>   - 120 줄 -> i <= PRI_MAX; 가 더 낫지... 않...? PRI_MAX-PRI_MIN로?<br>
<br>   - 125~126 줄 -> 삭제?<br>
<br>   - 137~138 줄 -> 고정 버퍼로...<br>
<br>   - 259~260 줄 -> 고친 이유 궁금<br>
<br>   - 285~286 줄 -> 삭제?<br>
<br>   - 290 줄 -> 삭제?<br>
<br>   - 366~367 줄 -> 삭제?<br>
<br>   - 534 줄 -> idx == ~가 더 낫지... 않...? idx == BITMAP_ERROR이면 expired와 교체 후에 스케줄해야 할 듯?<br>
<br>   - 591~610 줄 -> 삭제?<br>
<h2>preemption 추가 작성 요구</h2>
- thread_create, thread_unblock, thread_set_priority<br>
<br>   - 위의 3가지 함수를 사용하는 곳을 검색해서 코드 확인</li></ul>

<h1>박동민 조항준 코드 2차 동료검토(2009/10/13)</h1>
<h2>작성 코드 검토(thread.c)</h2>
177 줄 - if (~ && thread_ticks >= t->remained_ticks) 일 듯?<br>
<br>177~187 줄 - thread_ticks를 그냥 맨 앞에서 한번 thread_ticks++; 한 후에 뒤에서는 이미 ++되어 있다고 생각하는 것이 더 편할 듯? 그래야 괜히 +1, 중간 ++ 안 해도 될 듯...<br>
<br>
<br>thread_unblock - thread_unblock 선점 처리 구현 안 됨<br>
<br>
<br>thread_yield - thread_ticks가 remained_ticks를 넘어서서 yield가 불린 경우에 처리 문제. expired로 들어가야 하는데 active로 들어감. 수정에 노력이 좀 필요할 수도? 현재 thread_tick 함수 구현에서 이미 remained_ticks를 0으로 만들었으므로 여기서 그냥 thread_tick 함수에서 하듯이 thread_ticks가 remained_ticks(이 경우 항상 0)을 넘었으면 expired로 가게 처리하면 안 됨. remained_ticks을 thread_tick에서 0으로 안 만들게 하고 적당히 처리할 수도 있지만 저번에 논의된 대로 지나치게 thread_tick 함수와 thread_yield가 중복되는 문제가 있음<br>
<ul><li>저번에 말한대로 별도 bool 변수로 expired로 가야함을 알려주도록 하거나<br>
</li><li>최소한 공통 부분을 함수로 분리해야 함. is_thread_expired 등의 이름으로 새 함수를 만들고 거기서 remained_ticks가 0이 아니면 remained_ticks보다 thread_ticks가 큰지 체크, remained_ticks가 0이면 일반적인 Time Slice로 체크한 후에 expired로 가야하면 return true, active로 가야하면 return false 등을 하게 하고 thread_yield와 thread_tick 함수에서 해당 is_thread_expired를 사용하여 expired여부를 체크하게 하면 됨<br>
thread_set_priority - 우선 순위 비교 시 식이 PRI_MAX - idx > (unsigned)new_priority 일 듯? bitmap에서 찾지 못한 경우 처리도 해야 할 듯?<br>
<h2>세마포어 등 수정 구현 안 됨</h2>
아마도 thread_unblock을 안 짜서 오류가 아직 안 났을 듯? thread_unblock을 짜고 나면 make check 등을 통해서 테스트하면 애러가 나고 수정하게 될 듯?