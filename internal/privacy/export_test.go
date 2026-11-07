package privacy

import "os"

func chmod(path string, mode os.FileMode) error { return os.Chmod(path, mode) }
