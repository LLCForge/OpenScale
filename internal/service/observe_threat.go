package service

import "github.com/openscale/openscale/internal/filter"

func init() {
	denyTexts[filter.DenyThreatBlocked] = "Karşı cihaz bu cihazı taradığı için yeni bağlantıları bir süre reddediliyor (tehdit algılama). Engeli 'openscale threats unblock <cihaz>' veya panelden kaldırabilirsiniz."
}
