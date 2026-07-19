pub enum MythicError {
    // ── Codec（编解码）──────────────────────────────────
    Serialize,
    Deserialize,
    Base64,
    Utf8,
    InvalidPacket,
    InvalidUuid,
    UuidMismatch,
    Compression, // 新增：压缩/解压失败（如 gzip/zlib）

    // ── Crypto（加密）──────────────────────────────────
    Crypto,
    RsaKeyGen,
    RsaEncrypt,
    RsaDecrypt,
    AesEncrypt, // 拆开更精确
    AesDecrypt,
    KeyDerivation, // 密钥派生失败（如 PBKDF2/Scrypt）
    InvalidCiphertext,
    Signature, // 签名验签失败

    // ── Transport（网络传输，Agent 特定）─────────────
    Timeout,
    ConnectionFailed,
    DnsFailed,
    TlsFailed,
    TlsCertPinning, // 证书固定（Certificate Pinning）校验失败
    Http5XX,
    Http4XX,
    Proxy,
    ProxyAuthFailed, // 代理认证失败（NTLM/Basic/Digest）
    ProxyDns,        // 代理 DNS 解析失败
    SocketBind,      // 本地端口绑定失败（如用于 SOCKS5 或 Bind Shell）
    Websocket,       // WS/WSS 握手或帧解析失败
    RateLimited,     // 服务端限流或触发阈值

    // ── Protocol（C2 协议交互）─────────────────────────
    AuthFailed,
    ServerRejected,
    NotCheckedIn,
    PayloadTooLarge,
    KeyExchangeFailed,
    VersionMismatch, // 服务端与 Agent 协议版本不匹配
    ProtocolState,   // 状态机非法跳转（如未认证就发任务结果）

    // ── Task（本地任务调度与执行）─────────────────────
    CommandNotFound,     // 本地没有该命令的 Handler
    CommandPermDenied,   // 执行时权限不足（如需要 SYSTEM）
    CommandArgsFail,     // 参数解析失败
    InvalidTaskData,     // 服务下发的任务数据损坏
    TaskTimeout,         // 任务执行超时（被杀掉）
    TaskQueueFull,       // 任务队列堆积已满
    TaskCanceled,        // 任务被服务端取消或本地主动抛弃
    TaskOutputTruncated, // 输出结果太大，被截断以节省带宽

    // ── OS / Syscall（操作系统底层调用）──────────────
    Syscall,    // 通用系统调用失败（如 syscall 返回负值）
    NtStatus,   // 原生 NT API 返回错误状态（STATUS_*）
    WindowsApi, // Win32 API 返回错误（GetLastError）

    // ── Memory（内存操作，注入/加载核心）─────────────
    MemoryAlloc,   // VirtualAlloc / mmap 分配失败
    MemoryProtect, // VirtualProtect / mprotect 修改页属性失败
    MemoryFree,    // 释放内存失败
    RemoteWrite,   // WriteProcessMemory / ptrace 写入远程进程失败
    PeParsing,     // 解析 PE（Portable Executable）头失败
    Relocation,    // 重定位表应用失败（Reflective Loading）

    // ── Process / Thread（进程与线程）─────────────────
    ProcessSpawn,  // 创建新进程失败（CreateProcess）
    ProcessOpen,   // 打开进程句柄失败
    ProcessInject, // 注入流程失败（包含多种注入方式）
    ThreadCreate,  // 创建线程失败（CreateRemoteThread / RtlCreateUserThread）
    ThreadContext, // 获取/设置线程上下文失败（GetThreadContext）
    DllLoad,       // 加载 DLL 失败（LoadLibrary / LdrLoadDll）
    BofLoad,       // BOF（Beacon Object File）加载或执行失败

    // ── Filesystem / Registry（文件系统与注册表持久化）─
    FileOpen,
    FileRead,
    FileWrite,
    FileDelete,
    FilePermissions,
    DirectoryCreate,
    RegistryOpen,
    RegistryRead,
    RegistryWrite,
    RegistryDelete,

    // ── Persistence（持久化机制）──────────────────────
    ScheduledTask,  // 计划任务安装/触发失败
    ServiceInstall, // Windows 服务安装失败
    StartupFolder,  // 启动项目录写入失败

    // ── Evasion / Environment（规避与运行环境检测）───
    SandboxDetected,  // 检测到沙箱环境，主动中止
    DebuggerDetected, // 检测到调试器，主动中止
    AvHookDetected,   // 检测到 EDR/AV 挂钩，规避动作失败
    UnsupportedArch,  // 架构不匹配（如 x86 Agent 尝试注入 x64 进程）
    UnsupportedOs,    // 操作系统版本过低（如未达 Win10）

    // ── Sleep / Jitter（休眠与唤醒）───────────────────
    SleepInterrupted, // 异步信号/APC 打断了休眠
    WaitableTimer,    // 等待定时器失败
    JitterCalc,       // 抖动（Jitter）算法计算溢出

    // ── IPC（进程间通信，用于多进程/管道）─────────────
    PipeCreate,   // 命名管道创建失败
    PipeConnect,  // 管道连接失败
    SharedMemory, // 共享内存映射失败

    // ── Resource（本地资源限制）───────────────────────
    ResourceExhausted, // 句柄/内存耗尽
    PermissionDenied,
    IoFailed,
    OutOfMemory,  // 明确的内存溢出
    LockPoisoned, // Mutex/RwLock 中毒（Panic 后恢复）

    // ── Fallback（动态错误兜底）───────────────────────
    Os(String), // 操作系统相关，带额外信息
    Memory(String),
    Task(String),
    Transport(String),
    Evasion(String), // 规避模块抛出特定字符串错误

    // ── Internal（内部不可预知错误）───────────────────
    Panic,            // 捕获到了不可恢复的 Panic
    Internal(String), // 未分类的内部逻辑错误

    ArgsParseError,
    CommandExecError,
}
/// Convenience alias.
pub type MythicResult<T> = Result<T, MythicError>;
