package types

import (
	"bytes"
	"container/list"
	"errors"
	"io"

	"github.com/status-im/keycard-go/apdu"
)

type Metadata struct {
	name  string
	paths *list.List
}

func EmptyMetadata() *Metadata {
	return &Metadata{"", list.New()}
}

func NewMetadata(name string, paths []uint32) (*Metadata, error) {
	m := EmptyMetadata()

	if err := m.SetName(name); err != nil {
		return nil, err
	}

	for i := 0; i < len(paths); i++ {
		m.AddPath(paths[i])
	}

	return m, nil
}

func ParseMetadata(data []byte) (*Metadata, error) {
	buf := bytes.NewBuffer(data)
	header, err := buf.ReadByte()

	if err != nil {
		return nil, err
	}

	version := header >> 5

	if version != 1 {
		return nil, errors.New("invalid version")
	}

	namelen := int(header & 0x1f)
	cardName := string(buf.Next(namelen))

	list := list.New()

	for {
		start, err := apdu.ParseLength(buf)

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		count, err := apdu.ParseLength(buf)

		if err != nil {
			return nil, err
		}

		for i := start; i <= (start + count); i++ {
			insertOrderedNoDups(list, i)
		}
	}

	return &Metadata{cardName, list}, nil
}

func insertOrderedNoDups(list *list.List, num uint32) {
	le := list.Back()

	for le != nil {
		val := le.Value.(uint32)

		if num > val {
			break
		} else if num == val {
			return
		}

		le = le.Prev()
	}

	if le == nil {
		list.PushFront(num)
	} else {
		list.InsertAfter(num, le)
	}
}

func (m *Metadata) Name() string {
	return m.name
}

func (m *Metadata) SetName(name string) error {
	if len(name) > 20 {
		return errors.New("name longer than 20 chars")
	}

	m.name = name
	return nil
}

func (m *Metadata) Paths() []uint32 {
	listlen := m.paths.Len()
	paths := make([]uint32, listlen)
	e := m.paths.Front()

	for i := 0; i < listlen; i++ {
		paths[i] = e.Value.(uint32)
		e = e.Next()
	}

	return paths
}

func (m *Metadata) AddPath(path uint32) {
	insertOrderedNoDups(m.paths, path)
}

func (m *Metadata) RemovePath(path uint32) {
	for le := m.paths.Front(); le != nil; le = le.Next() {
		if path == le.Value.(uint32) {
			m.paths.Remove(le)
			return
		}
	}
}

func (m *Metadata) Serialize() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x20 | byte(len(m.name)))
	buf.WriteString(m.name)

	le := m.paths.Front()

	if le == nil {
		return buf.Bytes()
	}

	start := le.Value.(uint32)
	len := uint32(0)

	for le = le.Next(); le != nil; le = le.Next() {
		w := le.Value.(uint32)

		if w == (start + len + 1) {
			len++
		} else {
			apdu.WriteLength(buf, start)
			apdu.WriteLength(buf, len)
			start = w
			len = 0
		}
	}

	apdu.WriteLength(buf, start)
	apdu.WriteLength(buf, len)

	return buf.Bytes()
}
