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
sga-server device owner laptop alice@corp.test --by … --reason …   # 이 장비는 MCP 경로에서 항상 alice로 기록·판정 ('-'로 해제)
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

## 한 줄 설치 (3단계)

관제 서버가 설치에 필요한 것을 직접 준다(이미지를 만들 때 함께 빌드). LAN 게이트웨이의 18080(평문 HTTP)으로 받는다.

| 파일 | 내용 |
|---|---|
| `/install/install.ps1` | Windows 설치 스크립트. 이 서버의 주소와 아래 파일들의 SHA-256, CA 지문이 박혀 있다(ASCII, CRLF) |
| `/install/sg_advance-*.whl` | 센서 |
| `/install/requirements.txt` | 센서 의존성 전부, **해시 고정**(`uv export`). `pip --require-hashes --only-binary=:all:` |
| `/install/ca.pem` | 장비 CA |
| `/install/sg-advance-plugin.zip` | OpenClaw 플러그인(같은 파일이면 같은 바이트로 압축: 해시가 안 바뀜) |

**믿음의 사슬**: 설치 명령(관리자가 전달) → `install.ps1`의 SHA-256 → 나머지 파일의 SHA-256과 CA 지문 → 그 CA로만 서버 인증 → 등록 때 장비 인증서.
평문 HTTP 구간에서 무엇이 바뀌어도 해시가 달라 설치가 멈춘다. 등록 토큰은 평문으로 오가지 않는다(설치 명령 안에서 환경 변수로만 쓰고, 등록은 TLS).

```bash
# Mac (관리자): 노트북에 붙여 넣을 한 줄을 만든다. 1회용 등록 토큰이 들어 있다(24시간).
docker compose exec -e SGA_SERVER=http://127.0.0.1:8000 control-plane \
  sga-server device install --device-id laptop --user <직원 ID>
```

노트북의 PowerShell(관리자 권한 필요 없음)에 그 한 줄을 붙여 넣으면 `install.ps1`이 이렇게 한다.

1. 파일을 받아 해시 확인
2. `%LOCALAPPDATA%\SG-Advance\venv`에 Python 가상환경(3.12 이상: `py -3.13`/`py -3.12`/`python` 순서로 찾음)을 만들고 설치
3. 등록: 키를 노트북에서 만들고 CSR로 장비 인증서를 받음. 상태는 `%USERPROFILE%\.sg-advance`
4. OpenClaw가 있으면 플러그인 설치(`openclaw plugins install --link`), `sensorCli`를 venv의 `sga-sensor.exe`로 설정,
   `openclaw.json`의 게이트웨이 토큰을 `.sg-advance\openclaw-token`에 복사(출력하지 않음)해 센서가 게이트웨이도 보게 함, 게이트웨이 재시작
5. 로그인할 때 시작하게 등록(아래 4단계)

다시 실행하면 등록은 건너뛰고 센서·플러그인만 갱신한다(OpenClaw를 나중에 설치했을 때). 관제 서버를 다시 빌드하면 휠 해시가
바뀔 수 있으니 설치 명령은 마지막 빌드 뒤에 만든다(해시가 다르면 설치가 멈춘다: 안전한 쪽).

## Windows 이식 (4단계)

| 항목 | macOS·Linux | Windows |
|---|---|---|
| 서비스 | launchd LaunchAgent | 작업 스케줄러 작업 "SG-Advance Sensor"(로그온 시, 그 사용자로, 권한 상승 없음, 실패 시 1분마다 재시작), `pythonw`로 창 없이, 로그 `.sg-advance\logs\sensor.log`. 작업을 만들 수 없는 PC면 시작프로그램 폴더의 숨김 실행기 |
| 플러그인 ↔ 데몬 | 유닉스 소켓(0600) | 127.0.0.1의 임의 포트 + 실행마다 바뀌는 토큰. `.sg-advance\sga-api.json`에 `{host, port, token}`. 토큰 없는 요청은 거부 |
| 설치 탐지 | npm·nvm·pnpm·volta, launchd/systemd | `%APPDATA%\npm`, nvm-windows, pnpm, 작업 스케줄러의 OpenClaw 작업(`OpenClaw Gateway`), 시작프로그램 폴더 |
| 비밀 파일 권한 | 0600 확인 | 모드 비트가 없어 확인 생략(사용자 프로필 ACL에 맡김) |
| 문자 인코딩 | UTF-8 | OpenClaw 출력은 UTF-8로, `schtasks` 출력은 콘솔 코드 페이지로 읽음(한국어 Windows는 cp949) |

## 남은 단계

1. ~~장비 인증서~~ ✅, 2. ~~LAN 게이트웨이~~ ✅, 3. ~~한 줄 설치~~ ✅, 4. ~~Windows 이식~~ ✅ (자동 테스트만, 실기기 확인 전)
5. 노트북에 실제 설치, 노트북 OpenClaw 연결

## 한계

- 인증서 갱신이 아직 없다(만료 전에 다시 등록해야 함). 폐기 목록(CRL)은 쓰지 않고, 관제 서버가 장비마다 지문을 확인한다.
- 관리자 신원은 여전히 공용 관리자 토큰이다(SSO·개인 토큰은 별도 과제).
