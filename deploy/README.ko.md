# 기존 웹앱에 카나리 통합하기

[English guide](README.md)

이 문서는 카나리 사이드카를 기존 서비스의 지원 콘텐츠와 Nginx 가상 호스트에 연결한다. 저장소의 데모 사이트로 실제 앱을 대체하지 않는다. 카나리는 합성 데이터만 만들며, 확인 이벤트는 경보와 조사를 위한 탐색 신호다. 이 버전은 세션 자동 제한을 지원하지 않는다.

지원 링크는 일반적인 앱 점검 중에 이 경로를 발견할 수 있게 한다. 실행별 JavaScript는 단계별 값을 노출하지만 확인 요청을 보내지 않는다. 유효한 반사에는 HTML, JavaScript, JSON에 분산된 값을 결합하고, 합성 티켓을 받아 SHA-256을 계산한 뒤 최종 URL을 별도로 요청하는 행동이 필요하다. 정상적인 페이지 표시나 기본적인 링크 수집은 이 단계를 스스로 수행하지 않는다. 사람이나 목적에 맞춘 크롤러도 재현할 수 있으므로 이 이벤트는 ARTEX만의 지문이 아니라 행동 신호다. 설계 근거와 증거의 한계는 [탐지 신호 설명](../README.ko.md#왜-탐지-신호가-되는가)에 정리했다.

## 사용할 파일

| 파일 | 용도 |
| --- | --- |
| [`compose.production.yaml`](compose.production.yaml) | `127.0.0.1:19091`에서 카나리 사이드카만 실행 |
| [`production.env.example`](production.env.example) | 운영 설정 템플릿 |
| [`nginx/canary-rate-limit-http.conf`](nginx/canary-rate-limit-http.conf) | Nginx `http` 블록에 한 번 넣는 카나리 요청 및 연결 제한 |
| [`nginx/canary-location.conf`](nginx/canary-location.conf) | 기존 Nginx `server` 블록에 넣을 경로 설정 |
| [`content/support-link.html`](content/support-link.html) | HTML 지원 글에 넣을 링크 조각 |
| [`content/support-link.md`](content/support-link.md) | Markdown 또는 CMS 지원 글에 넣을 링크 조각 |
| [`check_integration.py`](check_integration.py) | 안전한 경로 점검과 명시적 전체 체인 점검 |

사이드카는 실행마다 `status.<digest>.js`와 `review.<digest>.js`를 생성한다. 앱의 정적 자산에 복사하거나 빌드에 삽입할 고정 JS 번들은 없다. 지원 링크가 실행별 `overview`를 열면 사이드카가 두 JS 응답을 생성한다. 지원 링크와 동일 출처 경로가 통합 지점이다. 보고된 ARTEX 30회 시험에서는 정적 번들 단독 구성을 평가하지 않았다.

## 1. 대상 앱 점검

비로그인 방문자나 공개 페이지 검사자가 접근할 수 있는 지원 글을 선택한다. 선택한 호스트에서 `/sys/sso-status/`가 비어 있고 실제 로그인 또는 SSO 시스템이 사용하지 않는지 확인한다. 현재 카나리 서버의 경로 접두사는 고정돼 있다. 앱이 이미 이 경로를 사용한다면 서버, 프록시, 콘텐츠 링크, 통합 점검을 함께 수정하고 다시 검증해야 한다.

실제 앱의 HTTPS 호스트명, 예를 들어 `app.example.com`을 사용한다. 모든 단계에서 Nginx가 동일한 `Host`를 사이드카에 전달해야 한다. 사이드카의 허용 목록은 호스트명을 확인하고 명시된 `Host` 포트까지 실행에 결속하지만 사용자 신원을 확인하지는 않는다. TLS와 가상 호스트 선택은 앞단 프록시에서 강제한다.

지원 글과 카나리 경로를 같은 출처에 둔다. 다른 호스트로 연결하면 시험한 동일 출처 구성이 아니다. 앱이나 edge가 카나리 경로에 Content Security Policy를 적용한다면 실행별 동일 출처 JS를 읽을 수 있는지 확인한다. 앱 전체 CSP를 완화하기 전에 해당 경로의 정책 충돌을 점검한다. 새 경로의 로그 보관 기간과 요청 속도 제한을 정한다. 일회용 게이트와 서명이 URL에 있으므로 edge, CDN, WAF, 분석 도구, 분산 추적의 쿼리 문자열 기록 여부를 확인한다.

사이드카의 `canary/server.py`에는 `Aster` 지원 헤더, 서비스 안내 문구, `SUP-6148`이 참고용 화면으로 들어 있다. 실제 서비스의 상태를 나타내는 정보가 아니다. 운영 배포 전 실제 지원 영역에 맞게 보이는 문구, 사건 식별자, JS 표현을 조정하고 실제 계정 또는 SSO 사고가 발생한 것처럼 안내하지 않는다. 이런 단서의 변경은 에이전트 행동을 바꿀 수 있으므로 통합 앱에서 일반 브라우저 대조군과 에이전트 반사 시험을 다시 진행한다. 기존 30회 시험의 비율이 수정된 콘텐츠에 그대로 적용되는 것은 아니다.

## 2. 사이드카 시작

비공개 저장소에 접근할 권한이 있는 환경에서 다음을 실행한다.

```sh
gh repo clone j0hndo/ARTEX-Defence
cd ARTEX-Defence
cp deploy/production.env.example deploy/production.env
```

시작 전에 `deploy/production.env`를 편집한다. `CANARY_ALLOWED_HOSTS`를 실제 공개 호스트명 또는 소유한 호스트명 목록으로 설정한다. 초기 배포에는 `CANARY_POLICY=observe`를 유지한다. 예상 트래픽에 맞춰 `CANARY_TTL_SECONDS`와 `CANARY_MAX_ACTIVE_RUNS`를 검토한다. 사이드카가 관측하는 직접 프록시 주소를 확인하고 그 프록시가 `X-Canary-Request-ID`를 덮어쓴다는 점을 검증하기 전까지 `CANARY_TRUSTED_PROXY_CIDRS`는 비워 둔다. 요청 ID를 억지로 기록하기 위해 넓은 컨테이너 대역이나 사설망 전체를 신뢰하지 않는다.

호스트 loopback 포트에는 같은 호스트의 다른 프로세스도 접속할 수 있다. Docker 포트 전달 때문에 이 호출자와 Nginx가 사이드카 안에서 같은 직접 피어로 보일 수도 있다. CIDR 일치만으로 요청 ID가 Nginx에서 생성됐다고 판단하지 않는다. 네트워크 또는 호스트 접근 제어로 게이트웨이만 접속할 수 있고 그 경계를 검증하기 전까지는 신뢰 프록시 CIDR을 비워 둔다. 그 후에도 요청 ID는 조사에 쓰는 연관 정보일 뿐, 자동 세션 제한의 충분한 근거가 아니다.

```sh
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml up -d --build --wait --wait-timeout 60
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml ps
curl -fsS http://127.0.0.1:19091/healthz
```

Compose는 사이드카를 호스트의 loopback에만 공개한다. 외부 사용자가 이 포트에 직접 접근하지 못하게 유지한다. `canary-production-logs` 볼륨의 `/var/log/canary/events.jsonl`에는 정제된 `canary_match` 이벤트만 남는다. 부분 단계의 이력은 기록하지 않는다. 실행 상태는 메모리에 있으므로 단일 사이드카 replica를 쓰거나 같은 실행의 모든 요청을 같은 replica로 라우팅한다. 재시작하면 진행 중인 실행은 무효화된다.

`overview` 방문마다 이후 단계를 진행하지 않더라도 메모리에 실행 하나가 생성된다. 예제의 최대 실행 수 1,024와 유효 시간 300초에서는 미완료 `overview` 방문이 초당 약 3.4회 지속되면 한도에 도달하고 새 `overview`가 HTTP 503을 반환할 수 있다. 아래 Nginx 제한은 인스턴스당 `overview`를 초당 2회, 순간 초과 10회로 설정한다. 모든 실행이 미완료라면 300초 동안 대략 610개가 쌓일 수 있다. 별도의 카나리 경로 전체 제한은 잘못된 경로 요청과 worker 부하를 제한한다. Nginx 인스턴스가 여럿이면 각 인스턴스의 제한은 공유되지 않는다. 전체 트래픽을 기준으로 실행 한도와 유효 시간을 정하고 쿼리 문자열을 남기지 않는 방식으로 429 및 503 횟수를 감시하며, 제한을 높이기 전에 통합 서비스를 부하 시험한다.

## 3. 기존 Nginx 호스트에 경로 추가

[`nginx/canary-rate-limit-http.conf`](nginx/canary-rate-limit-http.conf)를 Nginx의 바깥 `http { ... }` 블록에 한 번 넣는다. 그런 다음 [`nginx/canary-location.conf`](nginx/canary-location.conf)의 내용을 `app.example.com`에 해당하는 기존 HTTPS `server { ... }` 블록 안에 복사한다. `limit_req_zone`은 `http` 문맥에서만 정의할 수 있으므로 두 파일을 함께 사용해야 한다. 앱의 다른 경로, TLS 설정, 인증 규칙, upstream은 유지한다. 이 설정은 `/sys/sso-status/`만 `127.0.0.1:19091`로 전달한다. 앱에 더 넓은 `/sys/`나 전체 경로 location이 있다면 카나리 location의 우선순위를 확인한다.

설정 조각은 이 경로의 접근 로그와 일상적인 upstream 오류 로그를 끄고, 원래 `Host`를 전달하고, `X-Canary-Request-ID`를 생성하고, 클라이언트 인증 정보를 사이드카로 전달하지 않는다. `Host`를 `127.0.0.1`이나 사이드카 이름으로 바꾸지 않는다. 이 설정만으로는 앞단 CDN이나 WAF의 쿼리 기록을 막을 수 없으므로 모든 edge 계층을 점검한다.

더 낮은 속도 제한은 정확한 `/sys/sso-status/overview` 요청에만 적용된다. 잘못된 경로를 포함한 모든 `/sys/sso-status/` 요청에도 초당 10회, 순간 초과 20회, 동시 연결 32개, 요청 본문 1 KiB 제한을 적용한다. 앱의 다른 경로는 이 규칙에서 제외된다. 한도 초과 요청은 사이드카에 도달하기 전에 HTTP 429, 너무 큰 본문은 HTTP 413을 받는다. 이는 용량 제한이며 `canary_match` 신호가 아니다. `overview` 제한은 실행 상태 누적을, 전체 경로 제한은 실행을 만들지 않으면서 스레드를 생성하는 요청을 억제한다. 이 수치는 스테이징 부하 시험으로 조정해야 하며 Python 참고 서버를 고트래픽 서비스로 바꾸지는 않는다. Nginx 인스턴스 여럿이 한 사이드카로 전달한다면 공유 edge 제한도 설정한다. 로컬 프로세스가 19091 포트를 직접 호출하면 Nginx 제한을 우회하므로, 신뢰할 수 없는 작업이 있는 호스트에서는 사이드카 포트 공개를 없애고 사설망으로 연결하거나 호스트 접근 제어를 적용한다.

서비스의 통상적인 배포 절차에 따라 Nginx를 검증하고 다시 로드한다. 호스트가 직접 관리하는 Nginx라면 다음 명령을 사용할 수 있다.

```sh
sudo nginx -t
sudo nginx -s reload
```

Nginx 자체가 컨테이너에서 실행된다면 사이드카와 사설 공유 네트워크를 연결하고 `proxy_pass`를 사이드카 서비스 DNS 이름으로 바꾸며 호스트 loopback 포트 공개를 제거한다. 제공된 운영 파일은 Nginx가 Docker 호스트에서 실행된다는 가정이다. 다른 ingress를 쓰는 경우에도 동일한 조건을 구현한다. 정확한 경로 접두사, 공개 `Host` 보존, 클라이언트 쿠키 및 Authorization 미전달, 캐시 비활성화, 게이트웨이가 만든 요청 ID, 쿼리 문자열 미기록이 필요하다. upstream은 내부 주소에 묶고 공개 edge에서 HTTPS를 강제한다.

## 4. 지원 글에 진입점 추가

기존 HTML 지원 글에 [`content/support-link.html`](content/support-link.html)을 넣거나 Markdown 또는 CMS 지원 글에 [`content/support-link.md`](content/support-link.md)를 맞춰 삽입한다. 링크는 글과 같은 출처의 `/sys/sso-status/overview`를 가리킨다. 일반적인 지원 탐색 동선에서 보이도록 둔다. 기존 실험은 공개 지원 콘텐츠를 사용했으며, 숨긴 링크나 독립 정적 JS의 성능은 측정하지 않았다.

`overview` 응답이 자체 실행별 JS를 참조한다. 앱 셸에 카나리 `<script>`를 추가하거나 일반 브라우저 방문이 `verifySSOStatus`를 자동 호출하게 만들지 않는다.

## 5. 통합 점검

수정한 지원 글의 실제 경로를 사용해 공개 HTTPS 호스트에서 안전 점검을 실행한다.

```sh
python3 deploy/check_integration.py --base-url https://app.example.com --support-path /support
```

기본 점검은 지원 링크, `overview`, 실행별 discovery JS까지만 따라간다. 합성 티켓이나 확인 경로를 요청하지 않으므로 `canary_match`가 생기지 않아야 한다. 링크 누락, 출처 이탈, 형식 오류, 경로 장애가 있으면 실패한다. 실제 지원 경로를 지정하고 0이 아닌 종료 코드를 검토한다.

승인된 스테이징 환경에서는 전체 체인을 의도적으로 점검할 수 있다.

```sh
python3 deploy/check_integration.py --base-url https://staging.example.com --support-path /support --full-chain
```

`--full-chain`은 합성 티켓을 받고, 사건 안내와 review 자산을 읽고, SHA-256 서명을 계산해 일회성 확인 요청을 보낸다. 유효한 요청의 응답은 `observe`일 때 HTTP 200, `deny_verify`일 때 HTTP 403이다. `canary_match` 이벤트가 정확히 하나 생겨야 한다. 점검 도구는 게이트, 티켓, 서명, 쿼리 URL을 출력하지 않는다. 기준선 수집 중에는 `observe`를 쓰고, 계획된 점검은 자동 대응 규칙에서 제외한다.

의도적으로 전체 체인을 점검한 뒤 다음과 같이 이벤트를 확인한다.

```sh
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml exec canary \
  cat /var/log/canary/events.jsonl
```

## 6. 경보와 미끼 요청 제한

유효한 신호는 `GET /sys/sso-status/verifySSOStatus?run=RUN&gate=GATE&signature=SHA256_HEX` 요청이 **앞선** `overview → discovery JS → 합성 티켓 → 사건 안내 → review JS` 단계를 같은 호스트에서 유효 시간 내에 순서대로 마친 뒤 사이드카의 검증을 통과한 경우다. `SHA256_HEX`는 해당 실행의 합성 티켓 원문 UTF-8 바이트를 개행 없이 SHA-256으로 계산한 소문자 64자리 16진수 값이다. 게이트는 실행마다 생성되며 유효한 최종 확인 요청을 수락하면 그 실행은 소모된다. 확인 경로에 접근했거나 64자리 해시를 보냈다는 이유만으로 탐지 성공으로 보지 않는다.

사이드카는 유효한 최종 요청에만 `canary_match`를 기록한다. `CANARY_POLICY=observe`는 기록 후 200을 반환한다. `CANARY_POLICY=deny_verify`는 기록 후 **해당 위장 확인 요청에만** 403을 반환한다. 어느 설정도 에이전트의 다른 앱 요청을 자동 차단하지 않는다. [응답 정책 예시](../examples/policy/response-policy.yaml)는 후속 운영 안내이며, 서버가 읽거나 WAF에 설치하지 않는다.

경보에는 정제된 이벤트의 호스트, 실행 ID, 시각, 정책, 상태 코드와 신뢰된 요청 ID가 있는 경우 그 값을 사용한다. 게이트웨이가 사이드카에 접속하는 유일한 신뢰 경로임을 검증했다면, 게이트웨이가 생성한 `X-Canary-Request-ID`로 마지막 요청과 이벤트를 연결할 수 있다. Edge에는 쿼리 문자열 없이 요청 ID, 경로, 시각, 신뢰된 앱 세션을 기록할 수 있다. 계획된 통합 점검은 경보 대상에서 제외한다.

이 연결만으로는 앞선 다섯 단계를 마지막 요청자가 수행했는지 알 수 없다. 한 사람이 앞선 단계를 완료한 뒤 다른 사람의 브라우저가 최종 URL을 열도록 유도할 수 있다. 인증된 세션에 유일하게 연결돼도 무관한 마지막 요청자를 가리킬 수 있다. 따라서 이 버전의 `canary_match`는 경보와 수동 조사에만 사용한다. 세션이나 IP를 자동으로 추가 인증하거나 차단하지 않는다. 앱 전체의 자동 집행은 같은 신뢰된 행위자가 여섯 단계 모두를 수행했다는 별도 검증 수단과 최종 URL 재사용 및 세션 간 전달 방지책을 설계하고 시험한 뒤에만 고려해야 한다. 공유 NAT나 기업 게이트웨이에도 관련 없는 사용자가 있을 수 있다. 유효한 반사는 이 카나리에 의미론적으로 반응했다는 증거이지 ARTEX, Bash 사용, 악의성을 확정하는 증거가 아니다.

## 원복과 한계

지원 링크와 Nginx 카나리 location을 제거하고 Nginx를 검증 후 다시 로드한 다음 사이드카를 종료한다.

```sh
docker compose --env-file deploy/production.env -f deploy/compose.production.yaml down
```

명명된 이벤트 볼륨은 조직의 로그 보관 정책에 따라 보존하거나 삭제한다. 문서의 27/30 반사 결과는 이전 로컬 동적 CMS 실험에서 나온 값이며 이 강화된 배포 패키지의 수치가 아니다. 운영 신호로 사용하기 전에 해당 서비스 환경에서 앱과 에이전트를 검증한다.
