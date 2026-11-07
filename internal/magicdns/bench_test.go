package magicdns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// BenchmarkAnswerA is the MagicDNS case of the performance gate (#576).
func BenchmarkAnswerA(b *testing.B) {
	doc := testDoc()
	qb := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, RecursionDesired: true})
	if err := qb.StartQuestions(); err != nil {
		b.Fatal(err)
	}
	if err := qb.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("laptop.openscale.internal."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		b.Fatal(err)
	}
	q, err := qb.Finish()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if Answer(doc, q) == nil {
			b.Fatal("no answer")
		}
	}
}
