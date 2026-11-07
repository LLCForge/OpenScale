package trust

// commonWords is the local list of passwords and words attackers try
// first (#12). Entries are lowercase ASCII after the leet and Turkish
// folding in strength.go, and at least four letters long. The list is
// written for OpenScale; it is not copied from a password corpus.
var commonWords = []string{
	// Passwords in every leaked list.
	"password", "passwd", "pass", "qwerty", "letmein", "welcome", "admin", "administrator",
	"root", "login", "master", "secret", "default", "changeme", "trustno", "iloveyou",
	"love", "lovely", "monkey", "dragon", "shadow", "sunshine", "princess", "football",
	"baseball", "soccer", "superman", "batman", "starwars", "pokemon", "whatever", "freedom",
	"hello", "hunter", "killer", "ninja", "mustang", "access", "flower", "cookie",
	"cheese", "summer", "winter", "spring", "autumn", "michael", "jennifer", "jordan",
	"charlie", "thomas", "daniel", "robert", "jessica", "ashley", "andrew", "matrix",
	"computer", "internet", "google", "apple", "samsung", "microsoft", "windows", "linux",
	"server", "guest", "user", "test", "testing", "demo", "temp", "backup",
	"private", "network", "office", "company", "family", "friend", "money", "dollar",
	"orange", "banana", "purple", "silver", "golden", "diamond", "angel", "heaven",
	"blink", "zxcv", "asdf", "qwer", "abcd", "abcabc", "aaaa",
	// Project and product names someone may reuse.
	"openscale", "scale", "wireguard", "tailscale", "headscale", "netbird",
	"mesh", "panel", "anahtar", "kokanahtar",
	// Turkish passwords and frequent words.
	"parola", "sifre", "sifrem", "parolam", "gizli", "gizlisifre", "yonetici", "kullanici",
	"misafir", "deneme", "yedek", "kopya", "sistem", "bilgisayar", "seviyorum", "askim",
	"sevgilim", "bebegim", "canim", "hayatim", "kalbim", "melegim", "prenses", "aslan",
	"kartal", "kanarya", "galatasaray", "fenerbahce", "besiktas", "trabzonspor", "bursaspor",
	"cimbom", "fener", "turkiye", "istanbul", "ankara", "izmir", "antalya",
	"bursa", "konya", "adana", "mustafa", "mehmet", "ahmet", "ayse", "fatma",
	"emine", "hatice", "zeynep", "elif", "yusuf", "murat", "emre", "burak",
	"merve", "esra", "ozlem", "kemal", "ataturk", "allah", "bismillah", "inanc",
	"ozgurluk", "bayrak", "vatan", "millet", "huzur", "mutluluk", "guzel", "merhaba",
	"selam", "tamam", "evet", "hayir", "kedi", "kopek", "araba", "okul",
	"ogrenci", "ogretmen", "anne", "baba", "kardes", "abla",
}
