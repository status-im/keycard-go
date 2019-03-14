package keycard

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

type StartingPoint int

const (
	tokenMaster    = 0x6D // char m
	tokenSeparator = 0x2F // char /
	tokenHardened  = 0x27 // char '
	tokenDot       = 0x2E // char .

	hardenedStart = 0x80000000 // 2^31
)

const (
	StartingPointMaster StartingPoint = iota + 1
	StartingPointCurrent
	StartingPointParent
)

type parseFunc = func() error

type parser struct {
	r                    *strings.Reader
	f                    parseFunc
	pos                  int
	path                 []uint32
	start                StartingPoint
	currentToken         string
	currentTokenHardened bool
}

func newParser(path string) *parser {
	p := &parser{
		r: strings.NewReader(path),
	}

	p.reset()

	return p
}

func (p *parser) reset() {
	p.r.Seek(0, io.SeekStart)
	p.pos = 0
	p.start = StartingPointCurrent
	p.f = p.parseStart
	p.path = make([]uint32, 0)
	p.resetCurrentToken()
}

func (p *parser) resetCurrentToken() {
	p.currentToken = ""
	p.currentTokenHardened = false
}

func (p *parser) parse() (StartingPoint, []uint32, error) {
	for {
		err := p.f()
		if err != nil {
			if err == io.EOF {
				err = nil
			} else {
				err = fmt.Errorf("at position %d, %s", p.pos, err.Error())
			}

			return p.start, p.path, err
		}
	}

	return p.start, p.path, nil
}

func (p *parser) readByte() (byte, error) {
	b, err := p.r.ReadByte()
	if err != nil {
		return b, err
	}

	p.pos++

	return b, nil
}

func (p *parser) unreadByte() error {
	err := p.r.UnreadByte()
	if err != nil {
		return err
	}

	p.pos--

	return nil
}

func (p *parser) parseStart() error {
	b, err := p.readByte()
	if err != nil {
		return err
	}

	if b == tokenMaster {
		p.start = StartingPointMaster
		p.f = p.parseSeparator
		return nil
	}

	if b == tokenDot {
		b2, err := p.readByte()
		if err != nil {
			return err
		}

		if b2 == tokenDot {
			p.f = p.parseSeparator
			p.start = StartingPointParent
			return nil
		}

		p.f = p.parseSeparator
		p.start = StartingPointCurrent
		return p.unreadByte()
	}

	p.f = p.parseSegment

	return p.unreadByte()
}

func (p *parser) saveSegment() error {
	if len(p.currentToken) > 0 {
		i, err := strconv.ParseUint(p.currentToken, 10, 32)
		if err != nil {
			return err
		}

		if i >= hardenedStart {
			p.pos -= len(p.currentToken) - 1
			return fmt.Errorf("index must be lower than 2^31, got %d", i)
		}

		if p.currentTokenHardened {
			i += hardenedStart
		}

		p.path = append(p.path, uint32(i))
	}

	p.f = p.parseSegment
	p.resetCurrentToken()

	return nil
}

func (p *parser) parseSeparator() error {
	b, err := p.readByte()
	if err != nil {
		return err
	}

	if b == tokenSeparator {
		return p.saveSegment()
	}

	return fmt.Errorf("expected %s, got %s", string(tokenSeparator), string(b))
}

func (p *parser) parseSegment() error {
	b, err := p.readByte()
	if err == io.EOF {
		if len(p.currentToken) == 0 {
			return fmt.Errorf("expected number, got EOF")
		}

		if newErr := p.saveSegment(); newErr != nil {
			return newErr
		}

		return err
	}

	if err != nil {
		return err
	}

	if len(p.currentToken) > 0 && b == tokenSeparator {
		return p.saveSegment()
	}

	if len(p.currentToken) > 0 && b == tokenHardened {
		p.currentTokenHardened = true
		p.f = p.parseSeparator
		return nil
	}

	if b < 0x30 || b > 0x39 {
		return fmt.Errorf("expected number, got %s", string(b))
	}

	p.currentToken = fmt.Sprintf("%s%s", p.currentToken, string(b))

	return nil
}

func Parse(str string) (StartingPoint, []uint32, error) {
	p := newParser(str)
	return p.parse()
}
