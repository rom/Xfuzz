package daemon

import "github.com/rom/Xfuzz/internal/safety"

// trustedSpawner returns the process-creation boundary the daemon uses for its
// own workers.
//
// It is here, in one line, so that the exemption is visible: a worker is Xfuzz's
// own binary and is not confined, while every target that worker runs is. The
// alternative — the daemon reaching for os/exec directly — is what the
// architecture lint exists to prevent (ARCHITECTURE section 2).
func trustedSpawner() Spawner { return safety.NewTrustedSpawner() }
