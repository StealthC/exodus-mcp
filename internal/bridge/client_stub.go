//go:build !windows

package bridge

// NewNamedPipeClient returns an unavailable client on non-Windows hosts. The
// HTTP server remains testable there, but it cannot access a Windows pipe.
func NewNamedPipeClient(string, string) Client { return UnavailableClient() }
