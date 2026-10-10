// Config storage uses a read-only snapshot and a recoverable two-file commit.
// Explicit paths, ownership metadata and typed errors define the storage boundary.
package configstore

import (
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
)

type Snapshot struct {
	Path     string
	Data     []byte
	Hash     string
	Sections map[string]map[string]string
	Owned    map[string]domain.Profile
}
