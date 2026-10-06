import Foundation

#if canImport(Darwin)
    import Darwin
#elseif canImport(Glibc)
    import Glibc
#endif

/// Whether `path` matches the shell glob `pattern` the way `fnmatch(3)` with no flags
/// does: `*` matches any run of characters (`/` included), `?` one character, `[...]` a
/// bracket expression (`!` or `^` negates, `a-z` ranges), and a backslash escapes the next
/// character. POSIX platforms call `fnmatch` itself; Windows (WinCatalyst fork,
/// harmony/wincat), whose CRT has no `fnmatch`, runs the matcher below.
func hfGlobMatches(_ pattern: String, _ path: String) -> Bool {
    #if os(Windows)
        return _hfGlobMatch(Array(pattern.unicodeScalars), 0, Array(path.unicodeScalars), 0)
    #else
        return fnmatch(pattern, path, 0) == 0
    #endif
}

#if os(Windows)
    private func _hfGlobMatch(_ p: [Unicode.Scalar], _ pi: Int, _ s: [Unicode.Scalar], _ si: Int) -> Bool {
        var pi = pi, si = si
        while pi < p.count {
            let c = p[pi]
            switch c {
            case "*":
                // Collapse consecutive stars, then try every split point.
                while pi < p.count, p[pi] == "*" { pi += 1 }
                if pi == p.count { return true }
                var k = si
                while k <= s.count {
                    if _hfGlobMatch(p, pi, s, k) { return true }
                    k += 1
                }
                return false
            case "?":
                guard si < s.count else { return false }
                pi += 1; si += 1
            case "[":
                guard si < s.count else { return false }
                var j = pi + 1
                var negate = false
                if j < p.count, p[j] == "!" || p[j] == "^" { negate = true; j += 1 }
                var matched = false
                var first = true
                while j < p.count, p[j] != "]" || first {
                    first = false
                    var lo = p[j]
                    if lo == "\\", j + 1 < p.count { j += 1; lo = p[j] }
                    var hi = lo
                    if j + 2 < p.count, p[j + 1] == "-", p[j + 2] != "]" {
                        hi = p[j + 2]
                        if hi == "\\", j + 3 < p.count { hi = p[j + 3]; j += 1 }
                        j += 2
                    }
                    if lo.value <= s[si].value, s[si].value <= hi.value { matched = true }
                    j += 1
                }
                guard j < p.count else { return false }   // unterminated bracket: no match
                if matched == negate { return false }
                pi = j + 1; si += 1
            case "\\":
                guard pi + 1 < p.count, si < s.count, p[pi + 1] == s[si] else { return false }
                pi += 2; si += 1
            default:
                guard si < s.count, c == s[si] else { return false }
                pi += 1; si += 1
            }
        }
        return si == s.count
    }
#endif
