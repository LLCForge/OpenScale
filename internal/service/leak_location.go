package service

import "github.com/openscale/openscale/internal/leaktest"

// serviceLocale reads the time zone and language region for the location
// consistency line of the leak test (#404); tests replace it.
var serviceLocale = leaktest.LocalLocale
