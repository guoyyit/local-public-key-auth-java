# Local Public Key Authentication Service

一个**无中心化外部依赖**的本地公钥凭证认证服务（Spring Boot 3 / Java 17）。
客户端先注册与用户绑定的公钥凭证，随后登录时提交由私钥生成的断言；服务端本地完成
挑战签发、来源校验、签名验证、使用计数校验与凭证生命周期管理，所有状态以
原子写入的 JSON 文件持久化，重启后可恢复。

支持的凭证算法：

| 算法标识 | 密钥 / 签名 |
| --- | --- |
| `Ed25519` | RFC 8032，JDK 内置 |
| `EC_P256` | P-256（secp256r1）+ ECDSA-SHA256，签名接受 DER 或原始 64 字节 `R||S` |

公钥以 X.509 SubjectPublicKeyInfo 编码、标准 Base64 传输；签名与挑战使用
无填充 URL-safe Base64。

---

## 1. 认证流程

### 1.1 注册（attestation）

1. `POST /api/auth/register/start`
   请求：`{"userId":"alice","origin":"http://localhost:8080"}`
   服务端生成 **256 bit 随机挑战**，创建与 `userId`、`origin`、`sessionId` 绑定、
   带过期时间的注册会话，并立即持久化。
   响应：`sessionId / userId / challenge / expiresAt`。
2. 客户端生成密钥对，对以下**规范化字符串**（UTF-8）用私钥签名：

   ```
   LOCAL-PK-AUTH-V1:REGISTER
   userId={userId}
   origin={origin}
   challenge={challenge}
   credentialId={credentialId}
   ```
3. `POST /api/auth/register/complete`
   提交 `sessionId, userId, origin, credentialId, algorithm, publicKey, signature`。
   服务端在**一次原子事务**中完成全部校验后写入凭证并把会话标记为已消费：
   - 会话存在、未过期、未被消费；
   - 会话绑定的 `userId` 与 `origin` 与请求完全一致（错绑/错来源拒绝）；
   - `origin` 必须在 `auth.allowed-origins` 白名单中；
   - 公钥可解析且与声称的算法匹配（EC 必须是 P-256 曲线）；
   - `credentialId` 全局唯一，拒绝重复注册；
   - 签名必须能用提交的公钥验证通过。

   校验失败不会写入任何状态，会话仍可重新提交；成功后会话一次性失效。

### 1.2 登录断言（assertion）

1. `POST /api/auth/login/start`
   请求：`{"userId":"alice","origin":"http://localhost:8080"}`
   服务端生成新的随机登录挑战，与用户、来源绑定并持久化。
2. 客户端对规范化字符串签名：

   ```
   LOCAL-PK-AUTH-V1:ASSERT
   userId={userId}
   origin={origin}
   challenge={challenge}
   credentialId={credentialId}
   signCount={signCount}
   ```
3. `POST /api/auth/login/assert`
   提交 `challengeId, userId, origin, credentialId, signature, signCount`。
   服务端校验：
   - 挑战存在、未过期、未被消费（重放返回 `CHALLENGE_REPLAY`）；
   - 挑战绑定的用户、来源与请求一致；
   - 凭证属于该用户且处于启用状态；
   - 签名验证通过（失败**不消费**挑战，可重试）；
   - `signCount` **严格大于**服务端记录值，否则判定为凭证被克隆或回退
     （`CLONE_DETECTED`），挑战同时作废。
   计数更新与挑战消费在同一次原子提交中完成。

### 1.3 并发断言的计数处理

- 所有状态变更在 `AuthStore` 的单一锁内串行化，并在锁释放前落盘，因此计数更新
  天然原子，不会出现读改写交错。
- 同一凭证的并发断言若**乱序到达**（如计数 5 比 4 先到），服务端会在
  `auth.counter-gap-timeout-ms`（默认 2s）内短暂等待缺失的中间计数，而**不是**
  误判合法凭证为克隆；等待发生在存储锁之外，不阻塞其他凭证或其他用户。
- 超过等待窗口仍严格递增的计数按“计数器跳变”接受（符合 WebAuthn 对
  signature counter 的宽松语义）；计数未严格递增的合法签名一律拒绝。
- 同一计数值并发提交时，最多一个成功提交，其余返回 `CLONE_DETECTED`。

### 1.4 多凭证与生命周期

- 一个用户可注册任意数量凭证，登录时任一**有效**凭证均可通过。
- `GET /api/auth/users/{userId}/credentials` 列出该用户的全部凭证。
- `DELETE /api/auth/users/{userId}/credentials/{credentialId}`
  停用（注销）单个凭证；停用立即持久化，不影响同用户的其他凭证，凭证计数保留。

### 1.5 过期回收

- 注册会话与登录挑战默认 TTL 300 秒（`auth.registration-ttl-seconds` /
  `auth.challenge-ttl-seconds`）。
- 定时任务（默认 60s，`auth.cleanup.fixed-delay-ms`）回收过期记录；使用时也有
  惰性过期检查。
- 已消费记录保留到过期，便于在时间窗口内把“重放”与“未知 ID”区分开。
- 同一用户的并发注册获得不同的 `sessionId`/`challenge`，互不覆盖，各自一次性使用。

---

## 2. 持久化与重启恢复

- 状态文件：`${auth.data-dir}/auth-state.json`，包含凭证、注册会话、登录挑战三部分。
- 每次变更把**整份文档**写入唯一临时文件，再 `ATOMIC_MOVE`（不支持时退化为
  普通 rename + REPLACE）交换到目标路径，因此不存在半写入状态；持久化失败会
  回滚内存，保证内存与磁盘一致。
- 启动时若状态文件存在则整体加载：已注册凭证（含停用标记）、各凭证的
  `signCount`、进行中的注册会话/挑战均会恢复；未完成的注册不会留下半截凭证记录。

配置项（`application.properties`）：

| 属性 | 默认值 | 说明 |
| --- | --- | --- |
| `auth.data-dir` | `data` | 状态文件目录 |
| `auth.allowed-origins[0]` | `http://localhost:8080` | 允许的来源白名单 |
| `auth.registration-ttl-seconds` | `300` | 注册会话有效期 |
| `auth.challenge-ttl-seconds` | `300` | 登录挑战有效期 |
| `auth.counter-gap-timeout-ms` | `2000` | 乱序计数等待上限 |
| `auth.cleanup.fixed-delay-ms` | `60000` | 过期回收间隔 |

---

## 3. HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/register/start` | 申请注册挑战 |
| POST | `/api/auth/register/complete` | 提交公钥与注册签名 |
| POST | `/api/auth/login/start` | 申请登录挑战 |
| POST | `/api/auth/login/assert` | 提交断言（签名 + 计数） |
| GET | `/api/auth/users/{userId}/credentials` | 列出用户凭证 |
| DELETE | `/api/auth/users/{userId}/credentials/{credentialId}` | 停用凭证 |

错误响应统一为：`{"error":"ERROR_CODE","message":"..."}`。

---

## 4. 信任边界（Trust Boundaries）

- **客户端（持证方）→ 服务端**：公钥、凭证标识、签名均为不可信输入，必须经过
  格式校验、来源白名单、归属（用户/会话/挑战）绑定校验与密码学验证后才落盘。
- **来源（origin）边界**：服务端只接受白名单中的 origin，注册会话/登录挑战与
  origin 绑定，跨来源提交被拒绝。
- **挑战边界**：挑战 256 位 `SecureRandom` 随机数，一次性使用，绑定用户与注册/
  认证会话，带 TTL；不可预测、不可跨用户复用、不可重放。
- **克隆检测边界**：信任锚是“服务端持久化的上一次计数值”。客户端上报的
  `signCount` 本身不可信，只有在签名验证通过后才与锚点比较；不严格递增即视为
  克隆/回退。注意：计数机制只能检测**回退**，无法阻止两台克隆设备都从同一点
  单调向前，这与 WebAuthn signature counter 的安全模型一致。
- **存储边界**：状态文件位于本地受保护目录，整文档原子落盘；服务本身不依赖任何
  外部 IdP、数据库或网络服务。传输层机密性（TLS）与用户目录管理不在本服务范围内。

---

## 5. 错误码

| 错误码 | HTTP | 触发场景 |
| --- | --- | --- |
| `INVALID_REQUEST` | 400 | 缺少必填字段、JSON 格式错误、计数为负 |
| `INVALID_ORIGIN` | 400 | origin 不在白名单或与会话/挑战绑定来源不一致 |
| `MALFORMED_CREDENTIAL` | 400 | Base64/公钥无法解析、曲线不是 P-256、字段缺失 |
| `UNSUPPORTED_ALGORITHM` | 400 | 算法不是 `Ed25519` / `EC_P256` |
| `CREDENTIAL_EXISTS` | 409 | `credentialId` 已被注册 |
| `SESSION_NOT_FOUND` | 410 | 注册会话不存在或已被回收 |
| `SESSION_EXPIRED` | 410 | 注册会话已过期 |
| `SESSION_ALREADY_USED` | 409 | 注册会话已成功使用 |
| `CHALLENGE_NOT_FOUND` | 410 | 登录挑战不存在或已被回收 |
| `CHALLENGE_EXPIRED` | 410 | 登录挑战已过期 |
| `CHALLENGE_REPLAY` | 409 | 挑战已被消费后再次提交 |
| `USER_MISMATCH` | 403 | 请求用户与会话/挑战/凭证绑定用户不一致 |
| `UNKNOWN_CREDENTIAL` | 404 | 凭证不属于该用户或不存在 |
| `CREDENTIAL_DISABLED` | 403 | 凭证已被停用/注销 |
| `SIGNATURE_INVALID` | 401 | 注册或断言签名验证失败 |
| `CLONE_DETECTED` | 409 | 签名有效但计数未严格递增（克隆/回退） |
| `CONCURRENCY_CONFLICT` | 409 | 乱序等待期间线程被中断 |
| `INTERNAL_ERROR` | 500 | 服务端内部错误（如持久化失败） |

---

## 6. 自动化测试

```
mvn test
```

覆盖：

- `AuthFlowTests`：Ed25519/P-256 注册与登录、多凭证独立、坏签名、错误来源、
  错绑用户、挑战重放、克隆/回退计数、未知凭证、重复凭证 ID、畸形公钥、凭证停用。
- `ExpiryTests`：注册会话/登录挑战过期拒绝与定时回收、同用户并发注册会话互不
  覆盖且各自一次性。
- `ConcurrentAssertionTests`：20 个乱序并发断言全部成功且无克隆误判、同计数并发
  仅一个成功、计数原子更新到最终值。
- `PersistenceRestartTests`：用两个独立 Spring 上下文模拟进程重启，验证凭证、
  停用标记、计数、进行中会话的恢复，重启后克隆检测仍生效，状态文件始终是完整
  JSON 且无临时文件残留。
