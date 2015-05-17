# Introduction #

자 이제 시작! 선수쳤다 :)

# 주의 사항 #
가. 코드 작성 시 반드시 락(Semaphore 등)을 적절히 사용
<br>나. 일정 계획을 세우고 필요시 보고서에도 포함(마일스톤도 정의)<br>
<br>다. 디자인, 동료검토, 테스트<br>
<br>라. 상수는 #define을 이용할 것<br>
<br>마. 적절한 assert를 사용할 것<br>
<br>바. 추가 함수, 추가 변수 등에 주석 설명 반드시 포함(설명에 LOGOS-ADDED FUNCTION, LOGOS-ADDED VARIABLE 등 LOGOS 포함 주석 삽입), 수정 시 코드는 물론 주석도 수정<br>
<br>사. 함수 이름 등의 Name Convention 준수(소문자 기본, underline로 단어 구분. 예 : thread_create)<br>
<br>아. SVN Update를 자주 수행하여 빠른 충돌의 감지 요구<br>
<br>
<h1>체크리스트</h1>
가. 모든 데이터의 빠짐 없는 수정<br>
<br>나. 각 데이터의 초기화<br>
<br>다. 인터럽트 상태 확인 및 인터럽트 관련 ASSERT 삽입<br>
<br>라. 자원 공유 등 시 락 사용<br>
<br>마. sort 등이 stable할 필요 있는가? 한가?<br>
<br>바. Naming이 틀린 것은 없는가?<br>
<br>사. 인터럽트 상태에서 동적 메모리 할당, 해제 조심<br>
<br>아. 주석을 적절히 달았는가?<br>
<br>자. idle thread 관련 처리가 되었는가?<br>
<br>차. USERPROG 등의 define이 적절히 처리되었는가?<br>
<br>카. 메모리를 모두 해제하였는가?<br>
<br>마. 오류 가능 함수들을 오류 체크하였나? (예 : false 리턴 체크)<br>
<br>바. 락을 잡고 리턴, 종료되지는 않는가?