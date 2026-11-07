package plugin

// A tiny WebAssembly binary encoder for the tests, so no outside compiler
// is needed. Function bodies are written as opcode bytes; each test module
// carries the WAT it stands for in a comment.

const (
	i32 = 0x7f
	i64 = 0x7e
)

type wfunc struct {
	params, results []byte
	locals          int // extra i32 locals
	body            []byte
	export          string
}

type wdata struct {
	offset int32
	bytes  []byte
}

type wmod struct {
	importFunc bool // imports env.f () -> ()
	noMemory   bool
	memMin     uint32
	funcs      []wfunc
	data       []wdata
}

func uleb(v uint64) []byte {
	var b []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		b = append(b, c)
		if v == 0 {
			return b
		}
	}
}

func sleb(v int64) []byte {
	var b []byte
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && c&0x40 == 0) || (v == -1 && c&0x40 != 0) {
			return append(b, c)
		}
		b = append(b, c|0x80)
	}
}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func vec(n int, items ...[]byte) []byte { return cat(uleb(uint64(n)), cat(items...)) }

func str(s string) []byte { return cat(uleb(uint64(len(s))), []byte(s)) }

func section(id byte, payload []byte) []byte {
	return cat([]byte{id}, uleb(uint64(len(payload))), payload)
}

// Instruction helpers.
func i32c(v int32) []byte           { return cat([]byte{0x41}, sleb(int64(v))) }
func i64c(v int64) []byte           { return cat([]byte{0x42}, sleb(v)) }
func op(b ...byte) []byte           { return b }
func mem(o byte, off uint32) []byte { return cat([]byte{o}, uleb(0), uleb(uint64(off))) }
func lget(i byte) []byte            { return []byte{0x20, i} }
func lset(i byte) []byte            { return []byte{0x21, i} }

const (
	opIf       = 0x04
	opBlock    = 0x02
	opLoop     = 0x03
	opEnd      = 0x0b
	opBr       = 0x0c
	opBrIf     = 0x0d
	opReturn   = 0x0f
	opUnreach  = 0x00
	opI32Load8 = 0x2d // i32.load8_u
	opI32L16   = 0x2f // i32.load16_u
	opI64Load  = 0x29
	opI32Store = 0x36
	opStore8   = 0x3a
	opStore16  = 0x3b
	opI32Eq    = 0x46
	opI32GeU   = 0x4f
	opI32Add   = 0x6a
	opI64Eq    = 0x51
	blockVoid  = 0x40
)

func (m wmod) bytes() []byte {
	var types, funcIdx, exports, codes [][]byte
	base := 0
	if m.importFunc {
		base = 1
	}
	for i, f := range m.funcs {
		types = append(types, cat([]byte{0x60}, vec(len(f.params), f.params), vec(len(f.results), f.results)))
		funcIdx = append(funcIdx, uleb(uint64(i)))
		if f.export != "" {
			exports = append(exports, cat(str(f.export), []byte{0x00}, uleb(uint64(base+i))))
		}
		locals := vec(0)
		if f.locals > 0 {
			locals = vec(1, cat(uleb(uint64(f.locals)), []byte{i32}))
		}
		body := cat(locals, f.body, []byte{opEnd})
		codes = append(codes, cat(uleb(uint64(len(body))), body))
	}
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	importType := len(types)
	if m.importFunc {
		types = append(types, []byte{0x60, 0x00, 0x00})
	}
	out = append(out, section(1, vec(len(types), types...))...)
	if m.importFunc {
		out = append(out, section(2, vec(1, cat(str("env"), str("f"), []byte{0x00}, uleb(uint64(importType)))))...)
	}
	out = append(out, section(3, vec(len(funcIdx), funcIdx...))...)
	if !m.noMemory {
		minPages := m.memMin
		if minPages == 0 {
			minPages = 1
		}
		out = append(out, section(5, vec(1, cat([]byte{0x00}, uleb(uint64(minPages)))))...)
		exports = append(exports, cat(str("memory"), []byte{0x02}, uleb(0)))
	}
	out = append(out, section(7, vec(len(exports), exports...))...)
	out = append(out, section(10, vec(len(codes), codes...))...)
	if len(m.data) > 0 {
		var segs [][]byte
		for _, d := range m.data {
			segs = append(segs, cat([]byte{0x00}, i32c(d.offset), []byte{opEnd}, uleb(uint64(len(d.bytes))), d.bytes))
		}
		out = append(out, section(11, vec(len(segs), segs...))...)
	}
	return out
}

// The exchange buffer of every test module is at offset 1024 of a 64 KiB
// memory.
const testBuf = 1024

var (
	fnVersion = wfunc{results: []byte{i32}, body: i32c(ABIVersion), export: "osp_abi_version"}
	fnBuffer  = wfunc{results: []byte{i32}, body: i32c(testBuf), export: "osp_buffer"}
)

func hook(export string, locals int, body []byte) wfunc {
	return wfunc{params: []byte{i32}, results: []byte{i32}, locals: locals, body: body, export: export}
}

// setVerdict stores v at the buffer start and returns length 1.
func setVerdict(v int32) []byte {
	return cat(i32c(0), i32c(v), mem(opStore8, testBuf), i32c(1))
}

// exampleDNSBody is the body of the example plugin (testdata/ornek-engel.wat):
// block every name below the "example" top-level domain.
//
//	(local $nl i32)
//	(local.set $nl (i32.load16_u offset=1027 (i32.const 0)))
//	(if (i32.ge_u (local.get $nl) (i32.const 9))
//	  (then
//	    (if (i64.eq (i64.load (i32.add (local.get $nl) (i32.const 1021)))
//	                (i64.const 0x656c706d6178652e)) ;; ".example" little endian
//	      (then (i32.store8 offset=1024 (i32.const 0) (i32.const 2))
//	            (return (i32.const 1))))))
//	(i32.store8 offset=1024 (i32.const 0) (i32.const 0))
//	(i32.const 1)
var exampleDNSBody = cat(
	i32c(0), mem(opI32L16, testBuf+3), lset(1),
	lget(1), i32c(9), op(opI32GeU),
	op(opIf, blockVoid),
	lget(1), i32c(testBuf+5-8), op(opI32Add),
	mem(opI64Load, 0),
	i64c(0x656c706d6178652e), op(opI64Eq),
	op(opIf, blockVoid),
	i32c(0), i32c(int32(VerdictBlock)), mem(opStore8, testBuf),
	i32c(1), op(opReturn),
	op(opEnd),
	op(opEnd),
	setVerdict(int32(VerdictPass)),
)

func exampleModule() []byte {
	return wmod{funcs: []wfunc{fnVersion, fnBuffer, hook("osp_dns_query", 1, exampleDNSBody)}}.bytes()
}

// tagsDNSBody blocks when the request carries at least one client tag:
//
//	(local.set $nl (i32.load16_u offset=1027 (i32.const 0)))
//	(if (i32.load8_u offset=1029 (local.get $nl)) (then block))
//	pass
var tagsDNSBody = cat(
	i32c(0), mem(opI32L16, testBuf+3), lset(1),
	lget(1), mem(opI32Load8, testBuf+5),
	op(opIf, blockVoid),
	i32c(0), i32c(int32(VerdictBlock)), mem(opStore8, testBuf), i32c(1), op(opReturn),
	op(opEnd),
	setVerdict(int32(VerdictPass)),
)

// stripQueryBody cuts the URL at the first '?':
//
//	(local $i i32) (local $n i32)
//	(local.set $n (i32.load16_u offset=1025 (i32.const 0)))
//	(block (loop
//	  (br_if 1 (i32.ge_u (local.get $i) (local.get $n)))
//	  (br_if 1 (i32.eq (i32.load8_u offset=1027 (local.get $i)) (i32.const 63)))
//	  (local.set $i (i32.add (local.get $i) (i32.const 1)))
//	  (br 0)))
//	(i32.store8 offset=1024 (i32.const 0) (i32.const 1))
//	(i32.store16 offset=1025 (i32.const 0) (local.get $i))
//	(i32.add (local.get $i) (i32.const 3))
var stripQueryBody = cat(
	i32c(0), mem(opI32L16, testBuf+1), lset(2),
	op(opBlock, blockVoid), op(opLoop, blockVoid),
	lget(1), lget(2), op(opI32GeU), op(opBrIf, 1),
	lget(1), mem(opI32Load8, testBuf+3), i32c('?'), op(opI32Eq), op(opBrIf, 1),
	lget(1), i32c(1), op(opI32Add), lset(1),
	op(opBr, 0),
	op(opEnd), op(opEnd),
	i32c(0), i32c(1), mem(opStore8, testBuf),
	i32c(0), lget(1), mem(opStore16, testBuf+1),
	lget(1), i32c(3), op(opI32Add),
)

// fixedLocationBody answers with the URL stored at offset 0 by a data
// segment (memory.copy to the buffer).
func fixedLocationBody(n int32) []byte {
	return cat(
		i32c(testBuf+3), i32c(0), i32c(n), op(0xfc, 0x0a, 0x00, 0x00),
		i32c(0), i32c(1), mem(opStore8, testBuf),
		i32c(0), i32c(n), mem(opStore16, testBuf+1),
		i32c(n+3),
	)
}

var (
	// loop forever: (loop (br 0)) (i32.const 0)
	infiniteBody = cat(op(opLoop, blockVoid, opBr, 0, opEnd), i32c(0))
	// (if (i32.eq (memory.grow (i32.const 1000)) (i32.const -1)) (then unreachable)) (i32.const 0)
	growBody = cat(i32c(1000), op(0x40, 0x00), i32c(-1), op(opI32Eq), op(opIf, blockVoid, opUnreach, opEnd), i32c(0))
	trapBody = op(opUnreach)
	// rewrite A to 10.0.0.1: verdict 3, family 4, address, length 6
	rewriteBody = cat(
		i32c(0), i32c(int32(VerdictRewrite)), mem(opStore8, testBuf),
		i32c(0), i32c(4), mem(opStore8, testBuf+1),
		i32c(0), i32c(0x0100000a), mem(opI32Store, testBuf+2),
		i32c(6),
	)
)
