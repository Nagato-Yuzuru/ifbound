package policy

import (
	"fmt"

	"github.com/pelletier/go-toml/v2/unstable"
)

// Locate sets the line and column of e from the text b of the file that e
// came from. Parse does this for its own errors. A caller runs Locate for
// an error that comes later, such as one from Config.CheckUpstreams, when it
// still holds the text. Locate does nothing when e has a place already or
// when the text has none for e.
//
// Locate places only an error that Parse, ParseBytes, or CheckUpstreams
// returns. It leaves an error that a caller builds from the exported
// fields without a place: the text of Field can stand for more than one path
// in the file, for example a key "a.b" and the key b in the table a.
func (e *FieldError) Locate(b []byte) {
	if e.Line == 0 {
		e.locateIn(newIndex(b))
	}
}

func (e *FieldError) locateIn(x *index) {
	if e.Line != 0 {
		return
	}
	if r, ok := x.find(e.path); ok {
		e.Line, e.Column = x.pos(r)
	}
}

// index maps each field path in a file to the range of its first
// definition. It holds every prefix of a path (the tables of a dotted key
// or of a header), every array element, and the contents of inline tables.
// The one walk that builds it also finds the first duplicate key. The maps
// use fieldPath.enc as key, so two paths with the same text stay apart.
type index struct {
	parser   unstable.Parser
	places   map[string]unstable.Range
	implicit map[string]bool // paths that only a longer path has named so far
	explicit map[string]bool // paths that a key or a table header has defined
	dup      *FieldError     // the first key or table that the file defines twice
}

// newIndex indexes the file b. When b has a syntax error, the index holds
// the part of the file before it.
func newIndex(b []byte) *index {
	x := &index{
		places:   map[string]unstable.Range{},
		implicit: map[string]bool{},
		explicit: map[string]bool{},
	}
	x.parser.Reset(b)
	t := tableTracker{arrays: map[string]int{}}
	for x.parser.NextExpression() {
		e := x.parser.Expression()
		//nolint:exhaustive // the other kinds are comments and values: they define no path
		switch e.Kind {
		case unstable.Table:
			parts, at := keyOf(e)
			path, ranges := t.table(parts, at)
			x.define(path, ranges, true)
		case unstable.ArrayTable:
			parts, at := keyOf(e)
			// The prefixes of the element place the array itself, at its first header.
			elem, ranges := t.arrayTable(parts, at)
			x.define(elem, ranges, false)
		case unstable.KeyValue:
			x.keyValue(t.base, e)
		}
	}
	return x
}

// keyValue indexes a key-value node below the table at base, and its value.
func (x *index) keyValue(base fieldPath, kv *unstable.Node) {
	parts, at := keyOf(kv)
	path := base
	for _, part := range parts {
		path = path.add(keySeg(part))
	}
	x.define(path, at, true)
	x.value(path, kv.Value())
}

// value indexes the elements of an array and the keys of an inline table.
func (x *index) value(path fieldPath, v *unstable.Node) {
	switch v.Kind { //nolint:exhaustive // a scalar has no part below it
	case unstable.Array:
		it := v.Children()
		for i := 0; it.Next(); i++ {
			elem := path.add(idxSeg(i))
			// An array node has no range of its own: only its parent can place it.
			x.define(elem, []unstable.Range{it.Node().Raw}, false)
			x.value(elem, it.Node())
		}
	case unstable.InlineTable:
		it := v.Children()
		for it.Next() {
			x.keyValue(path, it.Node())
		}
	}
}

// define records the places of path and of each prefix of it. ranges holds
// the range of each step of the path, counted from its end: the steps in
// front of them belong to an enclosing table that the file has defined
// already. So a path takes the range of the step that ends it. A range of
// length zero names no place: define leaves it out. A path that is defined
// twice is a duplicate when check is true.
func (x *index) define(path fieldPath, ranges []unstable.Range, check bool) {
	skip := len(path) - len(ranges)
	at := func(i int) unstable.Range {
		if i < skip {
			return unstable.Range{}
		}
		return ranges[i-skip]
	}
	for i := 1; i < len(path); i++ {
		x.name(path[:i].enc(), at(i-1), true)
	}
	p := path.enc()
	r := at(len(path) - 1)
	if check {
		if x.explicit[p] && x.dup == nil {
			line, col := x.pos(r)
			x.dup = newFieldError(path, fmt.Errorf("%w: duplicate key", errSyntax))
			x.dup.Line, x.dup.Column = line, col
		}
		x.explicit[p] = true
	}
	x.name(p, r, false)
}

// name sets the place of p unless an earlier definition has set it. A
// definition of p replaces a place that only a longer path has set.
func (x *index) name(p string, r unstable.Range, implicit bool) {
	if r.Length == 0 {
		return
	}
	if _, ok := x.places[p]; ok && (implicit || !x.implicit[p]) {
		return
	}
	x.places[p] = r
	x.implicit[p] = implicit
}

// find returns the range of path, or of its nearest enclosing path that
// the file names.
func (x *index) find(path fieldPath) (unstable.Range, bool) {
	for n := len(path); n > 0; n-- {
		if r, ok := x.places[path[:n].enc()]; ok {
			return r, true
		}
	}
	return unstable.Range{}, false
}

// pos returns the line and column of the start of r. The column counts bytes.
func (x *index) pos(r unstable.Range) (line, column int) {
	s := x.parser.Shape(r).Start
	return s.Line, s.Column
}

// keyOf returns the parts of the key of a node, and the range of each part.
func keyOf(n *unstable.Node) (parts []string, ranges []unstable.Range) {
	it := n.Key()
	for it.Next() {
		parts = append(parts, string(it.Node().Data))
		ranges = append(ranges, it.Node().Raw)
	}
	return parts, ranges
}

// tableTracker follows the table that the current expression belongs to.
type tableTracker struct {
	base   fieldPath      // the path of the current table
	arrays map[string]int // number of headers so far of each array of tables, by path
}

// resolve gives the path of a header with an index on each array of tables
// in it: a table below [[policy]] belongs to the latest policy. The last
// part gets an index only when renameLast is true. An index step has the
// range of the part that it follows.
func (t *tableTracker) resolve(parts []string, at []unstable.Range, renameLast bool) (fieldPath, []unstable.Range) {
	var path fieldPath
	var ranges []unstable.Range
	for i, part := range parts {
		path = append(path, keySeg(part))
		ranges = append(ranges, at[i])
		if i == len(parts)-1 && !renameLast {
			break
		}
		if n := t.arrays[path.enc()]; n > 0 {
			path = append(path, idxSeg(n-1))
			ranges = append(ranges, at[i])
		}
	}
	return path, ranges
}

func (t *tableTracker) table(parts []string, at []unstable.Range) (fieldPath, []unstable.Range) {
	path, ranges := t.resolve(parts, at, true)
	t.base = path
	return path, ranges
}

// arrayTable returns the path of the new element of an array of tables, with
// its ranges.
func (t *tableTracker) arrayTable(parts []string, at []unstable.Range) (fieldPath, []unstable.Range) {
	array, ranges := t.resolve(parts, at, false)
	key := array.enc()
	elem := array.add(idxSeg(t.arrays[key]))
	ranges = append(ranges, at[len(at)-1])
	t.arrays[key]++
	t.base = elem
	return elem, ranges
}
