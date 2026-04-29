//go:build !linux

package serbridge

import "runtime"

// runtimeOS exists in its own build-tagged file because runtime.GOOS
// would constant-fold to "linux" inside the Linux build, making the
// stub message in bridge_other.go misleading. Splitting it keeps the
// stub error informative ("this is a darwin build") on the actual
// non-Linux target.
func runtimeOS() string { return runtime.GOOS }
