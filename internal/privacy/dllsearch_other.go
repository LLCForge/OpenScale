//go:build !windows

package privacy

// HardenDLLSearch is Windows only (#518): other systems do not search the
// program's folder for shared libraries.
func HardenDLLSearch() (measures, warnings []string) { return nil, nil }
