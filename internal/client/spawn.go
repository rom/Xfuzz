package client

import (
	"context"

	"github.com/rom/Xfuzz/internal/safety"
	"github.com/rom/Xfuzz/pkg/executor"
)

// spawnDaemon starts a private daemon in the background.
//
// Through the spawn boundary like everything else. The daemon is one of Xfuzz's
// own processes, so it is not confined — and the campaigns it runs are, by its
// own sandbox (ADR-0012, ADR-0022).
func spawnDaemon(binary, socket string) error {
	args := []string{binary}
	if socket != "" {
		args = append(args, "--socket", socket)
	}

	spawner := safety.NewTrustedSpawner()
	handle, err := spawner.Start(context.Background(), executor.ProcSpec{
		Path: binary,
		Args: args,
	})
	if err != nil {
		return err
	}
	// The handle is deliberately dropped: an auto-started daemon outlives the
	// command that started it, which is the point of campaigns being decoupled
	// from client lifetime. It is found again through its socket.
	_ = handle
	return nil
}
