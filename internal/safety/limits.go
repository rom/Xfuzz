package safety

import (
	"github.com/rom/Xfuzz/internal/platform"
	"github.com/rom/Xfuzz/pkg/campaign"
)

// LimitsFor turns a campaign's safety section into the platform's caps.
//
// One place rather than two: the worker builds a sandbox from these, and the
// API asks which of them the daemon's host can enforce before the campaign is
// accepted. A mapping that existed in both would be the one that drifted.
func LimitsFor(cfg *campaign.Resolved) platform.Limits {
	return platform.Limits{
		AddressSpaceBytes: uint64(cfg.Safety.MemoryLimit),
		Processes:         uint64(cfg.Safety.ProcessLimit),
		FileSizeBytes:     uint64(cfg.Safety.FileSizeLimit),
		CPUSeconds:        uint64(cfg.Safety.CPULimit.Std().Seconds()),
		// Never a core file: a fuzzer writes reproducers, not dumps, and a
		// target that dumps core on every crash fills the disk with them.
		DisableCore: true,
	}
}
