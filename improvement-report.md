# rust-shark 개선 보고서

작성일: 2026-07-03 · 분석 범위: `rust-shark-core` + `rust-shark-app` 전체 소스
분석 방법: 병렬 정밀 코드 리뷰 3계열(core 패킷 경로 / core 서비스 모듈 / app·TUI) + 베이스라인 빌드·테스트

## 1. 베이스라인

| 항목 | 결과 |
| --- | --- |
| `cargo build` | 성공 (29s, gnullvm 오프라인 vendor) |
| `cargo test` | 전체 통과 (core 131개 포함, exit 0) |
| `cargo clippy` | 실행 불가 — `cargo-clippy`가 `stable-x86_64-pc-windows-gnullvm` 툴체인에 미설치 |

## 2. 발견 사항 및 처리 결정

심각도 순. `[적용]` = 이번 수정에 포함, `[보류]` = 보고만 (사유 명시).

### 2-1. critical — 모니터 데몬 무한 메모리 성장 `[적용]`

- 위치: `flow/tracker.rs` (근본) + `monitor/correlate.rs:115,172` (증상)
- `FlowTracker.flows`는 용량 10,000의 `LruCache`인데, 완료 스냅샷(`completed_tx`)은 FIN/FIN·RST로 닫힐 때만 emit된다. LRU 용량 초과로 축출되는 흐름(UDP 전부, 반열림 TCP, FIN 유실)은 emit 없이 사라진다.
- 결과: 데몬의 `metas: HashMap<FlowKey, FlowMeta>`와 `LiveState.conns`는 `persist_closed()`(done_rx 소비)에서만 엔트리를 제거하므로 영원히 증가하고, IPC `LiveConnections`에 죽은 연결이 계속 노출된다.
- 수정: `FlowTracker::update`에서 신규 흐름 삽입이 LRU 축출을 유발할 때 축출 대상의 최종 스냅샷을 완료 싱크로 emit. 회귀 테스트 추가.

### 2-2. high — pcap 타임스탬프 `tv_usec * 1000` i32 오버플로 `[적용]`

- 위치: `capture/mod.rs:61`
- `tv_usec`는 다수 플랫폼에서 i32. 손상/조작된 pcap 파일이 큰 값을 담으면 `tv_usec * 1000 > i32::MAX` → debug 빌드 산술 오버플로 패닉, release에서는 잘못된 타임스탬프. `capture_loop`는 신뢰 불가 pcap 파일 경로에도 쓰인다.
- 수정: i64 승격 후 나노초 범위(0..=999,999,999)로 클램프.

### 2-3. high — TUI 필터 입력 멀티바이트 문자 패닉 `[적용]`

- 위치: `tui/mod.rs` FilterInput 핸들러 + `tui/filter_bar.rs:40`
- `filter_cursor`를 바이트 인덱스로 쓰면서 키 입력마다 ±1만 하므로, 한글 등 멀티바이트 문자 입력 시 커서가 char 경계를 벗어나 `String::insert/remove`가 즉시 패닉 (예: `/` 모드에서 `ä` 1글자 입력 → 다음 프레임 렌더 패닉).
- 수정: 커서 이동/삽입/삭제를 `len_utf8()` 단위로 통일, 렌더는 `is_char_boundary` 가드. 회귀 테스트 추가.

### 2-4. high — IPC 서버 뮤텍스 poisoning 시 스레드 패닉 `[적용]`

- 위치: `ipc/server.rs:48,53,143,165`
- 워커(correlate)는 `unwrap_or_else(|e| e.into_inner())`로 poisoning을 복구하는데 IPC 서버는 동일 뮤텍스를 `.unwrap()` → 워커가 락 보유 중 패닉하면 이후 모든 IPC 조회가 스레드 패닉으로 실패.
- 수정: 워커와 동일한 poisoning 복구 패턴으로 통일. (unix 전용 모듈 — Windows 환경에서 컴파일 검증 불가, 기계적 수정)

### 2-5. high — 알림 평가가 SQLite 트랜잭션 없이 다중 커밋 `[적용]`

- 위치: `alert/detectors.rs::evaluate_full` + `store/mod.rs`
- 이벤트당 upsert/note/insert 문 다수가 각각 암묵 커밋 → 핫패스 오버헤드 + 중간 실패 시 부분 상태 잔존 + `store` 뮤텍스 보유 시간 증가(IPC 경합).
- 수정: `Store::with_tx` 헬퍼 추가, `evaluate_full` 전체를 단일 트랜잭션(BEGIN IMMEDIATE/COMMIT, 실패 시 ROLLBACK)으로 래핑. 기존 alert 테스트로 검증.

### 2-6. high — Linux 프로세스 귀속이 패킷마다 `/proc` 전수 스캔 `[보류]`

- 위치: `process/linux.rs:47,102-135`
- `(addr,port)→inode`만 1초 캐시하고 `inode→pid` 역매핑은 매 호출 `/proc/*/fd` 전체 readlink. macOS/Windows 구현과 달리 캐시가 없어 데몬 핫패스에서 O(프로세스×fd).
- 보류 사유: 캐시 구조 재설계가 필요한 침습적 변경 + Linux 전용 코드라 이 환경(win32)에서 컴파일·동작 검증이 전혀 불가. 리프레시 시점에 `inode→(pid,name,exe)` 역맵을 만들어 캐시에 포함하는 방식을 권고.

### 2-7. medium — `tcp.port != N` 필터가 직관과 반대로 동작 `[적용]`

- 위치: `filter/eval.rs::match_port_either`
- `!=`도 OR 시맨틱이라 src=80, dst=50000 패킷이 `tcp.port != 80`에 매치(dst가 80이 아니므로). "포트 80 제외" 의도와 반대.
- 수정: `Ne`는 양쪽 포트 모두 값과 다를 때만 참(AND). 테스트 추가.

### 2-8. medium — 패킷 페이로드 이중 복사 (핫패스) `[적용]`

- 위치: `decode/mod.rs::decode_packet` (`data: raw.data.clone()`)
- `RawPacket.data`는 이미 캡처 스레드에서 `to_vec()`로 복사된 소유 버퍼인데 디코드에서 한 번 더 clone → 패킷당 힙 할당+memcpy 2회.
- 수정: `decode_packet(raw: RawPacket)`로 소유권 이전, `data`는 move. 호출부 4곳(app main·TUI 테스트·decode 테스트·monitor correlate) 동시 갱신.

### 2-9. medium — BROWSE 모드에서 링 축출 시 선택 인덱스 미클램프 `[적용]`

- 위치: `tui/mod.rs::drain_packets`
- follow=false + 필터 활성 상태에서 오래된 패킷 축출로 `visible_count`가 줄면 `selected`가 범위를 벗어나 목록/상세가 빈 화면이 됨(패닉은 아님).
- 수정: drain 말미에 follow 여부와 무관하게 `selected`를 `visible_count-1`로 클램프.

### 2-10. medium — 알림 자식 프로세스 좀비 누적 `[적용]`

- 위치: `notify/mod.rs:36,40`
- `osascript`/`notify-send`를 `spawn()` 후 `Child`를 즉시 드롭 → Unix에서 `wait()` 미호출로 좀비 프로세스가 상시 데몬에 누적.
- 수정: spawn 성공 시 리퍼 스레드에서 `wait()`.

### 2-11. medium — 연결 이력 저장 실패 침묵 `[적용]`

- 위치: `monitor/correlate.rs::persist_closed` (`let _ = ... insert_connection`)
- 디스크 가득참 등 지속 실패에도 로그 없음 → 핵심 기능(이력) 무음 유실.
- 수정: 실패 시 `eprintln!` 로깅 (`evaluate_full` 실패 로깅과 동일 패턴).

### 2-12. low `[적용]`

- `decode/http2.rs::decode_str` — `p + len` usize 오버플로 가능(32비트 타깃) → `checked_add` 사용.
- `decode/tls.rs::parse_tls_record` — 핸드셰이크 길이를 TLS 레코드 경계와 미대조 → `hs_len ≤ record_len - 4` 검증 추가.
- `flow/tracker.rs` — 재전송 판정이 u64 단순 승격 비교라 TCP 시퀀스 랩(4GB+) 시 정상 세그먼트 오탐 → wrapping 시퀀스 비교로 교체.
- `core/cli.rs` — `--buffer-size 0` 허용(사실상 패킷 1개만 유지되는 무음 열화) → 파싱 단계에서 1 이상 검증.

### 2-13. low `[보류]`

- `tui/mod.rs` `total_dropped` 항상 0 표시 — pcap `stats()` 배관 추가 필요(캡처 스레드가 핸들 소유). 별도 기능 작업으로 권고.
- `tui/views.rs` 오버레이가 매 프레임(30fps) 전체 링(최대 10만) 재집계 — 집계 캐시/1초 스로틀 권고. 침습적이라 보류.
- `tui/packet_list.rs` 가시 행마다 매 프레임 `analyze()` 재실행 — `threat`처럼 유입 시 1회 분석 저장 권고 (core 구조체 변경 수반).
- `inspect/mod.rs` `j/k` 이동 미클램프(하이라이트만 사라짐) — unix 전용, 행 수 배관 필요.
- `ipc/server.rs` Subscribe 스레드가 정지 시 `recv()` 무한 대기 — `recv_timeout` + stop 확인 권고.
- `monitor/daemonize.rs` `chdir`/`dup2` 반환값 미검사.
- `monitor/correlate.rs` 흐름 방향이 첫 패킷 방향으로 고정 — local_addrs 기반 판정으로 통일 권고 (unverified).
- `analysis/threat.rs` `busiest_dst()` 패킷당 윈도우 전체 재계산 — 증분 캐시 권고.
- `--snaplen` 음수/0 미검증 — libpcap 동작 미확인(unverified).
- clippy를 gnullvm 툴체인에 반입하면 정적 검증 커버리지 향상.

### 2-14. 양호 확인 (수정 불필요)

- 디코더 전반: 경계 검사(`checked_sub` + `get()`) 일관 적용, DNS 압축 포인터 재귀 제한, 패닉 경로 없음.
- 터미널 복구(패닉 훅), Ctrl-C, 채널 종료 처리, TUI usize 감산 가드, config 폴백.
- `flow/reassembly.rs` wrapping 산술·버퍼 회계, `alert/baseline.rs` EWMA 방어, pcap/pcapng 라이터 길이 계산.

## 3. 적용 결과

적용 항목 14건 전체 반영 완료. 회귀 테스트 5건 신규 추가 (core: LRU 축출 emit / 시퀀스 랩 / `!=` 포트, app: 멀티바이트 필터 커서 / BROWSE 클램프).

| 검증 | 결과 |
| --- | --- |
| `cargo build` | 성공 |
| `cargo test` | 전체 통과 — core 134 (기존 131 + 신규 3), app 10 (기존 8 + 신규 2) |
| `cargo fmt --check` | 클린 (수정 파일 rustfmt 정리 후) |
| `cargo clippy` | 실행 불가 (gnullvm 툴체인 미설치 — 기존과 동일) |
| 실행: `--help` / `list-interfaces` | 정상 (Npcap 인터페이스 열거 확인) |
| 실행: `read ok.pcap --json` | 정상 — Ethernet/IPv4/UDP 디코드·JSON 출력 확인 |
| 실행: `read badusec.pcap --json` (tv_usec=3,000,000) | 패닉 없음, 나노초 클램프(`…999999999Z`) 동작 확인 |
| 실행: `--buffer-size 0` | 파싱 단계 거부 확인 (exit 2) |
| 실행: `diff a.pcap b.pcap` | 정상 (common=1) |

검증 한계: `ipc/`·`monitor/`·notify의 macOS/Linux 분기 등 unix 전용 코드는 이 환경(win32)에서 컴파일되지 않아 해당 수정 4건(2-4, 2-8의 correlate 호출부, 2-10, 2-11)은 기계적 변경으로만 적용됨 — unix 빌드에서 확인 필요.
