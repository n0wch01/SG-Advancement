# 다른 PC의 센서 (M12)

다른 PC나 VM의 센서가 같은 LAN으로 관제 서버에 붙는다. 결정(2026-11-13): 첫 대상은 **Windows 게이밍 노트북**,
네트워크는 **같은 LAN**(Tailscale 없음), 센서는 **관제 서버가 직접 배포**한다.

```
노트북 센서 ── https://<Mac LAN IP>:18443 (mTLS: 장비 인증서) ──▶ lan-gateway (nginx) ──▶ control-plane:8000
            ── http://<Mac LAN IP>:18080/install/ (설치 파일, 해시 고정) ──┘
Mac의 브라우저·CLI ── http://127.0.0.1:18100 (대시보드, 관리 API: LAN에서는 안 보임)
```

## 장비 인증서

- 관제 서버가 **장비용 인증 기관(CA)**을 가진다(EC P-256, 처음 시작할 때 `/data/ca`에 생성, 키 0600).
- 센서가 등록할 때 **키를 직접 만들고**(밖으로 나가지 않음) 서명 요청(CSR)을 보낸다. 서버는 CSR의 이름은 무시하고
  등록된 장비 ID로 서명한 클라이언트 인증서(기본 365일)를 돌려준다.
- 센서는 설치 명령에 들어 있는 **CA 지문(SHA-256)**으로 CA 파일을 확인하고, 그 CA로 서명된 서버만 믿는다.
  등록 응답의 CA가 고정한 CA와 다르면 아무것도 저장하지 않는다.
- 서버는 장비 토큰을 **인증서 지문에 묶는다**. LAN으로 등록한 장비는 매 요청마다 자기 인증서를 내야 하고,
  토큰만으로는(유출돼서 내부망에서 직접 써도) 401이다. 다른 장비의 인증서도 401.
- compose 안의 센서(팀 게이트웨이 등)는 지금처럼 토큰만 쓴다. 이 장비들은 LAN 게이트웨이로 들어오면 401이다.

## LAN 게이트웨이

`docker compose --profile lan up -d` (nginx, [deploy/lan-gateway](../deploy/lan-gateway/default.conf.template)).

| 경로 (18443, TLS) | 조건 |
|---|---|
| `/healthz`, `/v1/enroll` | 클라이언트 인증서 없이 (등록은 1회용 등록 토큰 + CSR 필수) |
| 그 밖의 `/v1/…` (센서 API) | 장비 CA가 서명한 클라이언트 인증서 필수(없으면 nginx가 403) |
| `/v1/admin/…` | 항상 403 |
| 나머지(대시보드 등) | 404 |

- nginx는 검증한 인증서를 **프록시 비밀값**(`SGA_PROXY_SECRET`)과 함께 넘긴다. 관제 서버는 비밀값이 맞을 때만 그 헤더를 믿고,
  인증서가 자기 CA에서 나온 것인지 한 번 더 확인한다. 내부망의 다른 컨테이너가 헤더를 꾸며도 소용없다.
- 포트는 `SGA_LAN_TLS_PORT`(기본 18443), `SGA_LAN_INSTALL_PORT`(기본 18080), 바인드 주소는 `SGA_LAN_BIND`(기본 전체).
  8443은 이 Mac에서 다른 프로젝트가 쓰고 있어 18443으로 정했다.

## 준비 (Mac, 한 번)

```bash
# .env: SGA_PROXY_SECRET=<임의의 긴 값>
docker compose up -d --build control-plane
docker compose exec control-plane sga-server tls server-cert --host <Mac LAN IP> --host <이름>.local
docker compose --profile lan up -d lan-gateway
docker compose exec control-plane sga-server tls ca          # 설치 명령에 넣을 CA 지문
docker compose exec -e SGA_SERVER=http://127.0.0.1:8000 control-plane sga-server device token --label laptop
```

Mac의 IP가 바뀌면 `server-cert`를 다시 만들고 `lan-gateway`를 재시작한다.

## 등록과 폐기

```bash
sga-sensor enroll --server https://<Mac LAN IP>:18443 --token set_… --device-id laptop \
  --ca-file ca.pem --ca-sha256 <CA 지문>
sga-server device list                     # 인증서 만료일, 마지막 접속, 폐기 여부
sga-server device revoke laptop --by … --reason …    # 토큰·인증서 즉시 거부 (T11)
sga-server device tokens | revoke-token ID           # 아직 안 쓴 등록 토큰 폐기
```

폐기된 센서는 `policy: refused (… device revoked)`를 보고, **마지막으로 받은 서명된 정책으로 계속 판정**한다
(끊겼다고 보호가 꺼지지 않게). 다시 쓰려면 새 등록 토큰과 새 장비 ID로 등록한다.

## 실환경 확인 (2026-11-13, Mac 자신에게 LAN 주소로)

| 시도 | 결과 |
|---|---|
| 등록(CA 지문 고정, CSR) → 정책 받기 | 성공. 키·인증서·CA 0600 저장 |
| 토큰만, 인증서 없이 `/v1/policy` | 403 (nginx) |
| 토큰 + 인증서 | 200 |
| 인증서가 있어도 `/v1/admin/devices` | 403 |
| 대시보드 | 404 |
| 인증서 헤더·프록시 비밀값 위조 | 403 |
| 인증서만, 토큰 없이 | 401 |
| CA를 지정하지 않은 접속 | TLS 검증 실패 |
| `device revoke` 뒤 동기화 | 401 `device revoked` → 센서는 `refused`, 캐시 정책 유지 |

시험 장비 `m12-mac-test`는 폐기된 상태로 목록에 남아 있다.

## 남은 단계

1. ~~장비 인증서~~ ✅, 2. ~~LAN 게이트웨이~~ ✅
3. 관제 서버가 센서 wheel·`install.ps1`·CA를 `/install/`로 제공, PowerShell 한 줄 설치(해시 고정)
4. Windows 이식: 플러그인 연결(유닉스 소켓 대신), 설치 탐지 경로, 로그온 작업 등록
5. 노트북에 실제 설치, 노트북 OpenClaw 연결

## 한계

- 인증서 갱신이 아직 없다(만료 전에 다시 등록해야 함). 폐기 목록(CRL)은 쓰지 않고, 관제 서버가 장비마다 지문을 확인한다.
- 관리자 신원은 여전히 공용 관리자 토큰이다(SSO·개인 토큰은 별도 과제).
