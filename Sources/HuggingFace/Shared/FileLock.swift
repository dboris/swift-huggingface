import Foundation

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#elseif os(Windows)
    // Windows (WinCatalyst fork, harmony/wincat): the lock file is opened through the CRT
    // (`_wopen`, an `int` descriptor like the POSIX arms) and locked with
    // `LockFileEx` / `UnlockFileEx` on its OS handle -- the `flock(2)` equivalent
    // (exclusive, fail-immediately for the non-blocking attempt). See the
    // `os(Windows)` helpers at the bottom of this file.
    import CRT
    import WinSDK
#else
    #error("FileLock is only supported on Darwin, Linux (Glibc) and Windows platforms.")
#endif

/// POSIX file permission bits,
/// expressed as an octal value (e.g. `0o644`).
///
/// This is a thin wrapper around the C `mode_t` type
/// used by `open(2)` and `fchmod(2)`.
#if os(Windows)
    // The CRT has no `mode_t`; the value is accepted and unused (NTFS ACLs, not mode bits).
    public typealias FilePermissions = Int32
#else
    public typealias FilePermissions = mode_t
#endif

/// A file-based lock for coordinating access to shared resources
/// across concurrent tasks and processes.
///
/// `FileLock` creates a `.lock` companion file next to the protected path
/// and uses `flock(2)` for mutual exclusion.
/// Nested ``withLock(blocking:_:)`` calls within the same task
/// are reentrant and do not deadlock.
public struct FileLock: Sendable {
    /// The path to the `.lock` file.
    public let lockPath: URL

    /// Maximum number of acquisition attempts after the initial try,
    /// or `nil` to retry indefinitely.
    public let maxRetries: Int?

    /// Seconds to wait between retry attempts.
    public let retryDelay: TimeInterval

    /// POSIX permissions applied when creating the lock file.
    public let mode: FilePermissions

    /// When `true`, acquisition retries up to ``maxRetries`` times;
    /// when `false`, a single failed attempt throws immediately.
    public let blocking: Bool

    // Reentrant locking is scoped to the current task identity,
    // not task-local values inherited by child tasks.
    private static let ownerIDGenerator = OwnerIDGenerator()

    /// Creates a file lock that protects the resource at `path`.
    ///
    /// The lock file is placed at `path` with an appended `.lock` extension.
    ///
    /// - Parameters:
    ///   - path: The path to the resource being protected.
    ///   - maxRetries: Maximum retry attempts before giving up,
    ///     or `nil` to retry indefinitely.
    ///     Defaults to `5`.
    ///   - retryDelay: Seconds between retries.
    ///     Defaults to `1.0`.
    ///   - mode: POSIX permissions for the lock file.
    ///     Defaults to `0o644`.
    ///   - blocking: Whether to retry on contention.
    ///     Defaults to `true`.
    public init(
        path: URL,
        maxRetries: Int? = 5,
        retryDelay: TimeInterval = 1.0,
        mode: FilePermissions = 0o644,
        blocking: Bool = true
    ) {
        self.lockPath = path.appendingPathExtension("lock")
        self.maxRetries = maxRetries
        self.retryDelay = retryDelay
        self.mode = mode
        self.blocking = blocking
    }

    /// Acquires an exclusive lock, executes `body`, then releases.
    ///
    /// Nested calls within the same task are reentrant
    /// and do not block.
    ///
    /// - Parameters:
    ///   - blocking: Overrides the instance-level ``blocking`` setting
    ///     for this single invocation.
    ///   - body: The work to perform under the lock.
    /// - Returns: The value returned by `body`.
    /// - Throws: ``FileLockError/acquisitionFailed(_:attempts:totalWaitTime:)``
    ///   if the lock cannot be obtained,
    ///   or any error thrown by `body`.
    public func withLock<T>(
        blocking: Bool? = nil,
        _ body: () async throws -> T
    ) async throws -> T {
        let context = await FileLockContext.shared(for: lockPath.path(percentEncoded: false))

        let currentTaskID: UInt64
        if let taskID = Self.currentTaskID() {
            currentTaskID = taskID
        } else {
            currentTaskID = await Self.ownerIDGenerator.nextID()
        }

        // Fast path: reentrant acquisition only within the same task.
        if await context.tryReentrantAcquire(taskID: currentTaskID) {
            do {
                let result = try await body()
                await context.decrementCounter()
                return result
            } catch {
                await context.decrementCounter()
                throw error
            }
        }

        // Slow path: acquire the underlying flock.
        let shouldBlock = blocking ?? self.blocking
        try await acquireLock(context: context, ownerTaskID: currentTaskID, blocking: shouldBlock)

        do {
            let result = try await body()
            await releaseLock(context: context, force: false)
            return result
        } catch {
            await releaseLock(context: context, force: false)
            throw error
        }
    }

    /// Returns a stable hash for the currently running task.
    private static func currentTaskID() -> UInt64? {
        withUnsafeCurrentTask { task in
            guard let task else { return nil }
            var hasher = Hasher()
            task.hash(into: &hasher)
            return UInt64(bitPattern: Int64(hasher.finalize()))
        }
    }

    /// Opens (or creates) the lock file, returning its file descriptor.
    ///
    /// Parent directories are created as needed.
    /// `O_NOFOLLOW` prevents symlink-based attacks on non-Windows platforms.
    private func openLockFile() throws -> Int32 {
        try FileManager.default.createDirectory(
            at: lockPath.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        #if os(Windows)
            // `_wopen` is variadic (unavailable to Swift); `_wsopen_s` is its fixed-arity form.
            var fd: Int32 = -1
            // The URL's file-system representation, not `path(percentEncoded:)`: the latter keeps a
            // leading `/` before the drive letter on Windows, which the CRT rejects with EINVAL.
            let nativePath = lockPath.withUnsafeFileSystemRepresentation { $0.map { String(cString: $0) } }
                ?? lockPath.path(percentEncoded: false)
            let status = nativePath.withCString(encodedAs: UTF16.self) {
                _wsopen_s(&fd, $0, _O_RDWR | _O_CREAT | _O_TRUNC | _O_BINARY, _SH_DENYNO, _S_IREAD | _S_IWRITE)
            }
            guard status == 0, fd >= 0 else {
                throw FileLockError.openFailed(lockPath, errno: status != 0 ? status : errno)
            }
            return fd
        #else
            var flags: Int32 = O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW

            let fd = open(lockPath.path(percentEncoded: false), flags, mode)
            guard fd >= 0 else {
                throw FileLockError.openFailed(lockPath, errno: errno)
            }

            // Apply permissions (may silently fail if not the file owner).
            _ = fchmod(fd, mode)
            return fd
        #endif
    }

    /// Result of a single non-blocking `flock(2)` attempt.
    private enum LockResult {
        case success
        case wouldBlock
        case notSupported
        case error(Int32)
    }

    /// Attempts a non-blocking exclusive `flock(2)`,
    /// automatically retrying on `EINTR`.
    private func tryLock(_ fd: Int32) -> LockResult {
        #if os(Windows)
            guard let handle = _hfOSHandle(fd) else { return .error(Int32(ERROR_INVALID_HANDLE)) }
            var overlapped = OVERLAPPED()
            if LockFileEx(handle, DWORD(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY), 0, 1, 0, &overlapped) {
                return .success
            }
            let code = GetLastError()
            if code == DWORD(ERROR_LOCK_VIOLATION) || code == DWORD(ERROR_IO_PENDING) { return .wouldBlock }
            return .error(Int32(bitPattern: code))
        #else
            var result: Int32
            repeat {
                result = flock(fd, LOCK_EX | LOCK_NB)
            } while result == -1 && errno == EINTR

            if result == 0 { return .success }

            switch errno {
            case ENOSYS: return .notSupported
            case EWOULDBLOCK, EAGAIN: return .wouldBlock
            default: return .error(errno)
            }
        #endif
    }

    /// Polls `tryLock` in a retry loop with `Task.sleep` between attempts.
    ///
    /// The file descriptor is closed on any error path
    /// (including `CancellationError` from `Task.sleep`).
    private func acquireLock(
        context: FileLockContext,
        ownerTaskID: UInt64,
        blocking: Bool
    ) async throws {
        let fd = try openLockFile()
        let startTime = Date()
        var attempt = 0

        do {
            while true {
                switch tryLock(fd) {
                case .success:
                    await context.recordAcquisition(fd: fd, ownerTaskID: ownerTaskID)
                    return
                case .notSupported:
                    throw FileLockError.notSupported(lockPath)
                case .error(let errnum):
                    throw FileLockError.lockFailed(lockPath, errno: errnum)
                case .wouldBlock:
                    if !blocking {
                        throw FileLockError.acquisitionFailed(
                            lockPath,
                            attempts: 1,
                            totalWaitTime: 0
                        )
                    }
                    if let maxRetries, attempt >= maxRetries {
                        throw FileLockError.acquisitionFailed(
                            lockPath,
                            attempts: attempt + 1,
                            totalWaitTime: Date().timeIntervalSince(startTime)
                        )
                    }
                    attempt += 1
                    try await Task.sleep(for: .seconds(retryDelay))
                }
            }
        } catch {
            _hfCloseDescriptor(fd)
            throw error
        }
    }

    /// Decrements the reentrant lock counter and,
    /// if it reaches zero (or `force` is `true`),
    /// unlocks and closes the file descriptor.
    ///
    /// Lock files are intentionally retained after release
    /// to avoid race conditions with concurrent acquirers.
    private func releaseLock(context: FileLockContext, force: Bool) async {
        if let fd = await context.releaseIfReady(force: force) {
            _hfUnlockDescriptor(fd)
            _hfCloseDescriptor(fd)
        }
    }
}

// MARK: - Platform helpers (unlock / close a lock descriptor)

#if os(Windows)
    /// The OS handle behind a CRT descriptor, or nil when it is not valid.
    private func _hfOSHandle(_ fd: Int32) -> HANDLE? {
        let raw = _get_osfhandle(fd)
        guard raw != -1, raw != -2, let handle = HANDLE(bitPattern: raw) else { return nil }
        return handle
    }

    /// `UnlockFileEx` on the byte `LockFileEx` locked (the `flock(fd, LOCK_UN)` equivalent).
    private func _hfUnlockDescriptor(_ fd: Int32) {
        guard let handle = _hfOSHandle(fd) else { return }
        var overlapped = OVERLAPPED()
        _ = UnlockFileEx(handle, 0, 1, 0, &overlapped)
    }

    private func _hfCloseDescriptor(_ fd: Int32) {
        _ = _close(fd)
    }
#else
    private func _hfUnlockDescriptor(_ fd: Int32) {
        flock(fd, LOCK_UN)
    }

    private func _hfCloseDescriptor(_ fd: Int32) {
        close(fd)
    }
#endif

/// Monotonically increasing counter for unique lock-owner identifiers.
private actor OwnerIDGenerator {
    private var nextOwnerID: UInt64 = 0

    func nextID() -> UInt64 {
        nextOwnerID &+= 1
        return nextOwnerID
    }
}

// Multiple FileLock instances targeting the same path share a single
// FileLockContext through this registry,
// so the underlying file descriptor is opened only once per path.
// Weak references allow contexts to be deallocated
// when no FileLock is actively using them.
private actor WeakContextRegistry {
    private final class WeakBox {
        weak var value: FileLockContext?
        init(_ value: FileLockContext) { self.value = value }
    }

    private var contexts: [String: WeakBox] = [:]

    /// Returns an existing context for `path`,
    /// or creates and caches a new one.
    func getOrCreate(_ path: String) -> FileLockContext {
        if contexts.count > 100 {
            contexts = contexts.filter { $0.value.value != nil }
        }

        if let existing = contexts[path]?.value {
            return existing
        }

        let context = FileLockContext()
        contexts[path] = WeakBox(context)
        return context
    }
}

private let contextRegistry = WeakContextRegistry()

/// Per-path mutable state backing one or more ``FileLock`` instances.
///
/// Tracks the open file descriptor, the owning task's identifier,
/// and a reentrant lock counter.
/// All mutations are serialized by the actor,
/// so compound check-and-mutate operations are atomic.
private actor FileLockContext {
    private var fileDescriptor: Int32?
    private var ownerTaskID: UInt64?
    private var lockCounter: Int = 0

    /// Releases the file descriptor on deallocation
    /// to prevent leaked descriptors if the context
    /// is collected while still holding a lock.
    deinit {
        if let fd = fileDescriptor {
            _hfUnlockDescriptor(fd)
            _hfCloseDescriptor(fd)
        }
    }

    static func shared(for path: String) async -> FileLockContext {
        await contextRegistry.getOrCreate(path)
    }

    /// Increments the lock counter if `taskID` matches the current owner,
    /// enabling reentrant acquisition without a second `flock(2)` call.
    ///
    /// - Returns: `true` if the caller is the current owner
    ///   and the counter was incremented.
    func tryReentrantAcquire(taskID: UInt64) -> Bool {
        if self.ownerTaskID == taskID {
            lockCounter += 1
            return true
        }
        return false
    }

    /// Stores the file descriptor and task owner after a successful `flock(2)`,
    /// resetting the counter to `1`.
    func recordAcquisition(fd: Int32, ownerTaskID: UInt64) {
        fileDescriptor = fd
        self.ownerTaskID = ownerTaskID
        lockCounter = 1
    }

    /// Decrements the lock counter (floored at zero)
    /// without releasing the underlying file descriptor.
    func decrementCounter() {
        lockCounter = max(0, lockCounter - 1)
    }

    /// Decrements the counter and returns the file descriptor to close
    /// when the counter reaches zero (or `force` is `true`).
    ///
    /// - Returns: The file descriptor to unlock and close,
    ///   or `nil` if the lock should be retained.
    func releaseIfReady(force: Bool) -> Int32? {
        guard fileDescriptor != nil else { return nil }
        lockCounter -= 1

        if lockCounter <= 0 || force {
            let fd = fileDescriptor
            fileDescriptor = nil
            ownerTaskID = nil
            lockCounter = 0
            return fd
        }

        return nil
    }
}

/// Errors that can occur during file locking operations.
public enum FileLockError: Error, LocalizedError, Sendable {
    /// The lock could not be acquired within the allowed attempts.
    case acquisitionFailed(URL, attempts: Int, totalWaitTime: TimeInterval)

    /// The lock file could not be opened.
    case openFailed(URL, errno: Int32)

    /// `flock(2)` failed with an unexpected (non-retryable) error.
    case lockFailed(URL, errno: Int32)

    /// The filesystem does not support `flock(2)` (`ENOSYS`).
    case notSupported(URL)

    public var errorDescription: String? {
        switch self {
        case .acquisitionFailed(let path, let attempts, let totalWaitTime):
            "Failed to acquire file lock at \(path.path(percentEncoded: false)) "
                + "after \(attempts) attempt\(attempts == 1 ? "" : "s") "
                + "(\(String(format: "%.1f", totalWaitTime))s)"
        case .openFailed(let path, let errno):
            "Failed to open lock file at \(path.path(percentEncoded: false)): "
                + String(cString: strerror(errno))
        case .lockFailed(let path, let errno):
            "Failed to lock file at \(path.path(percentEncoded: false)): "
                + String(cString: strerror(errno))
        case .notSupported(let path):
            "Filesystem does not support flock at: "
                + path.path(percentEncoded: false)
        }
    }
}
