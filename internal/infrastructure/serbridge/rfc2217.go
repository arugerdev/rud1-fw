//go:build linux

package serbridge

import (
	"encoding/binary"

	"github.com/rs/zerolog/log"
)

// Minimal RFC 2217 (Com Port Control Option) implementation.
//
// The full spec covers a dozen subnegotiations; for our use case
// (avrdude programming an Arduino over the bridge) we only need:
//
//   - SET-BAUDRATE          (101) — 4 bytes big-endian
//   - SET-DATASIZE          (102) — 1 byte (5/6/7/8)
//   - SET-PARITY            (103) — 1 byte (1=none, 2=odd, 3=even)
//   - SET-STOPSIZE          (104) — 1 byte (1=1, 2=2, 3=1.5)
//   - SET-CONTROL           (105) — 1 byte (DTR/RTS/flow)
//   - PURGE-DATA            (108) — 1 byte (1=in, 2=out, 3=both)
//   - NOTIFY-LINESTATE      (106) — outbound only, we don't drive this
//   - NOTIFY-MODEMSTATE     (107) — outbound only
//
// Every other IAC sequence we strip from the byte stream so the serial
// device never sees the framing bytes (0xff is a valid byte for serial
// payloads, so we have to be careful — RFC 2217 mandates `IAC IAC` to
// pass a literal 0xff byte through, which the parser handles).
//
// Anything we don't recognise is silently dropped to avoid clobbering
// the device with stray bytes; loud rejection would also work but the
// MVP keeps the noise low.

// Telnet command bytes (IAC = Interpret As Command).
const (
	iac  byte = 0xff
	iacWill byte = 0xfb
	iacWont byte = 0xfc
	iacDo   byte = 0xfd
	iacDont byte = 0xfe
	iacSB   byte = 0xfa // sub-negotiation begin
	iacSE   byte = 0xf0 // sub-negotiation end
	iacNop  byte = 0xf1
	iacBrk  byte = 0xf3 // break (we don't propagate)
)

// Telnet options we might see negotiated.
const (
	optBinary    byte = 0x00 // 0
	optEcho      byte = 0x01 // 1
	optSGA       byte = 0x03 // 3 — Suppress Go Ahead
	optComPort   byte = 0x2c // 44 — RFC 2217 Com Port Control Option
)

// Com-Port-Option subcommand codes (client → server side).
const (
	cpcSetBaudRate byte = 1
	cpcSetDataSize byte = 2
	cpcSetParity   byte = 3
	cpcSetStopSize byte = 4
	cpcSetControl  byte = 5
	cpcNotifyLineState byte = 6
	cpcNotifyModemState byte = 7
	cpcFlowControlSuspend byte = 8
	cpcFlowControlResume byte = 9
	cpcSetLineStateMask byte = 10
	cpcSetModemStateMask byte = 11
	cpcPurgeData         byte = 12
)

// SET-CONTROL values (subset). Only DTR/RTS bits matter for our use
// case; others are flow-control variants we don't synthesize.
const (
	ctrlReqFlowState     byte = 0
	ctrlSetNoFlow        byte = 1
	ctrlSetXONXOFF       byte = 2
	ctrlSetRTSCTS        byte = 3
	ctrlReqBreakState    byte = 4
	ctrlSetBreakOn       byte = 5
	ctrlSetBreakOff      byte = 6
	ctrlReqDTRState      byte = 7
	ctrlSetDTROn         byte = 8 // assert DTR
	ctrlSetDTROff        byte = 9 // deassert DTR
	ctrlReqRTSState      byte = 10
	ctrlSetRTSOn         byte = 11
	ctrlSetRTSOff        byte = 12
)

// iacParser is a small state machine that walks an inbound TCP byte
// stream, surfaces "passthrough" bytes (the actual serial payload)
// and returns any 2217 reply bytes we owe the client.
type iacParser struct {
	sess *linuxSession
	state iacState
	cmd   byte // last command byte after IAC (e.g. SB)
	sub   []byte // accumulated sub-negotiation payload
	// dtrOn / rtsOn track the last applied modem-control state so a
	// SET-CONTROL ReqDTRState can be answered without an extra ioctl.
	dtrOn bool
	rtsOn bool
}

type iacState int

const (
	stateData iacState = iota
	stateIAC
	stateOption
	stateSubneg
	stateSubnegIAC
)

func newIACParser(sess *linuxSession) *iacParser {
	return &iacParser{
		sess:  sess,
		state: stateData,
		dtrOn: true, // serial port comes up with DTR asserted by default
		rtsOn: true,
	}
}

// Feed pushes a chunk of inbound TCP bytes through the parser. Returns:
//   - serial: bytes that should be written to the underlying serial fd
//   - reply:  bytes the server owes the client (RFC 2217 acknowledgements)
//
// The parser handles partial sequences across calls — the state machine
// persists in the parser struct, so a sub-negotiation split across two
// reads is reassembled correctly.
func (p *iacParser) Feed(in []byte) (serial []byte, reply []byte) {
	for _, b := range in {
		switch p.state {
		case stateData:
			if b == iac {
				p.state = stateIAC
				continue
			}
			serial = append(serial, b)

		case stateIAC:
			switch b {
			case iac:
				// Escaped 0xff in the data stream.
				serial = append(serial, iac)
				p.state = stateData
			case iacSB:
				p.state = stateOption
				p.sub = p.sub[:0]
			case iacWill, iacWont, iacDo, iacDont:
				p.cmd = b
				p.state = stateOption
			case iacNop, iacBrk:
				// Ignore — we don't propagate Telnet break to the serial
				// port, callers can use the dedicated reset endpoint.
				p.state = stateData
			default:
				// Unknown IAC verb — swallow the next byte if any (most
				// telnet verbs are 2 bytes) and resume.
				p.state = stateData
			}

		case stateOption:
			// Two paths: WILL/WONT/DO/DONT carry one option byte and
			// we're done; SB carries an option byte then a payload.
			if p.cmd == iacWill || p.cmd == iacWont || p.cmd == iacDo || p.cmd == iacDont {
				reply = append(reply, p.handleNegotiation(p.cmd, b)...)
				p.cmd = 0
				p.state = stateData
				continue
			}
			// Sub-negotiation: option byte first, then we accumulate
			// until IAC SE.
			p.sub = append(p.sub, b)
			p.state = stateSubneg

		case stateSubneg:
			if b == iac {
				p.state = stateSubnegIAC
				continue
			}
			p.sub = append(p.sub, b)

		case stateSubnegIAC:
			if b == iacSE {
				// End of sub-negotiation. Process the payload.
				reply = append(reply, p.handleSubneg(p.sub)...)
				p.sub = p.sub[:0]
				p.state = stateData
			} else if b == iac {
				// Escaped 0xff inside SB payload.
				p.sub = append(p.sub, iac)
				p.state = stateSubneg
			} else {
				// Malformed — abort the SB and resume in data state.
				p.sub = p.sub[:0]
				p.state = stateData
			}
		}
	}
	return serial, reply
}

// handleNegotiation processes WILL/WONT/DO/DONT for an option. We
// only care about COM-PORT-OPTION (44); for everything else we reply
// with the symmetric refusal so the client doesn't keep asking. Telnet
// negotiation rules:
//
//   - DO  reply WILL  if we accept the option, WONT to refuse
//   - WILL reply DO   if we want it, DONT to refuse
//   - WONT/DONT — ack with same direction
//
// The actual bytes (BINARY, ECHO, SGA) we accept silently because the
// usual desktop client (a TCP-to-COM bridge) is going to send them as
// part of standard Telnet startup.
func (p *iacParser) handleNegotiation(cmd, opt byte) []byte {
	switch opt {
	case optComPort:
		// Accept COM-PORT-OPTION. We reply with WILL on DO, DO on
		// WILL (mutual acceptance).
		switch cmd {
		case iacDo:
			return []byte{iac, iacWill, optComPort}
		case iacWill:
			return []byte{iac, iacDo, optComPort}
		case iacDont, iacWont:
			return []byte{iac, iacWont, optComPort}
		}
	case optBinary, optEcho, optSGA:
		// Accept binary mode and SGA, refuse server-side echo (the
		// serial device echoes its own data on demand). Mirror the
		// expected reply per Telnet rules.
		switch cmd {
		case iacDo:
			if opt == optEcho {
				return []byte{iac, iacWont, opt}
			}
			return []byte{iac, iacWill, opt}
		case iacWill:
			return []byte{iac, iacDo, opt}
		case iacDont, iacWont:
			return []byte{iac, iacWont, opt}
		}
	}
	// Unknown option — refuse symmetrically.
	switch cmd {
	case iacDo:
		return []byte{iac, iacWont, opt}
	case iacWill:
		return []byte{iac, iacDont, opt}
	}
	return nil
}

// handleSubneg processes a complete sub-negotiation payload. The first
// byte is the option, the rest is option-specific. We only act on
// COM-PORT-OPTION; everything else is silently ignored.
func (p *iacParser) handleSubneg(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	if payload[0] != optComPort {
		return nil
	}
	if len(payload) < 2 {
		return nil
	}
	subCmd := payload[1]
	args := payload[2:]
	switch subCmd {
	case cpcSetBaudRate:
		if len(args) != 4 {
			return nil
		}
		baud := int(binary.BigEndian.Uint32(args))
		if baud > 0 {
			if err := p.applyBaud(baud); err != nil {
				log.Warn().Err(err).Int("baud", baud).Msg("serial bridge: set baud failed")
			}
		}
		// Reply with the applied (or queried) speed.
		return p.replyBaud()

	case cpcSetDataSize:
		if len(args) != 1 {
			return nil
		}
		bits := int(args[0])
		if bits >= 5 && bits <= 8 {
			if err := p.applyFraming(bits, p.parity(), p.stopBits()); err != nil {
				log.Warn().Err(err).Int("dataBits", bits).Msg("serial bridge: set data size failed")
			}
		}
		return p.replyFraming(cpcSetDataSize)

	case cpcSetParity:
		if len(args) != 1 {
			return nil
		}
		parity := decodeParity(args[0])
		if parity != "" {
			if err := p.applyFraming(p.dataBits(), parity, p.stopBits()); err != nil {
				log.Warn().Err(err).Str("parity", parity).Msg("serial bridge: set parity failed")
			}
		}
		return p.replyFraming(cpcSetParity)

	case cpcSetStopSize:
		if len(args) != 1 {
			return nil
		}
		stop := decodeStopSize(args[0])
		if stop != "" {
			if err := p.applyFraming(p.dataBits(), p.parity(), stop); err != nil {
				log.Warn().Err(err).Str("stop", stop).Msg("serial bridge: set stop size failed")
			}
		}
		return p.replyFraming(cpcSetStopSize)

	case cpcSetControl:
		if len(args) != 1 {
			return nil
		}
		switch args[0] {
		case ctrlSetDTROn:
			p.dtrOn = true
			_ = setControlLines(p.sess.serialFD, p.dtrOn, p.rtsOn)
		case ctrlSetDTROff:
			p.dtrOn = false
			_ = setControlLines(p.sess.serialFD, p.dtrOn, p.rtsOn)
		case ctrlSetRTSOn:
			p.rtsOn = true
			_ = setControlLines(p.sess.serialFD, p.dtrOn, p.rtsOn)
		case ctrlSetRTSOff:
			p.rtsOn = false
			_ = setControlLines(p.sess.serialFD, p.dtrOn, p.rtsOn)
		case ctrlReqDTRState:
			// fall through to reply
		case ctrlReqRTSState:
			// fall through to reply
		case ctrlSetNoFlow, ctrlSetXONXOFF, ctrlSetRTSCTS:
			// Flow control is best-effort — we don't apply it because
			// avrdude doesn't use flow control on its uploads.
		}
		// Reply with current state.
		var state byte
		switch args[0] {
		case ctrlReqDTRState, ctrlSetDTROn, ctrlSetDTROff:
			if p.dtrOn {
				state = ctrlSetDTROn
			} else {
				state = ctrlSetDTROff
			}
		case ctrlReqRTSState, ctrlSetRTSOn, ctrlSetRTSOff:
			if p.rtsOn {
				state = ctrlSetRTSOn
			} else {
				state = ctrlSetRTSOff
			}
		default:
			state = args[0]
		}
		return []byte{iac, iacSB, optComPort, cpcSetControl + 100, state, iac, iacSE}

	case cpcPurgeData:
		// We don't emulate buffer purges — the kernel manages tx/rx
		// buffers and the impact on avrdude is negligible. Acknowledge
		// the request so the client doesn't retry.
		if len(args) != 1 {
			return nil
		}
		return []byte{iac, iacSB, optComPort, cpcPurgeData + 100, args[0], iac, iacSE}
	}
	return nil
}

// applyBaud, applyFraming, and the small accessors below mutate the
// session's recorded settings AND the kernel termios state. The
// session struct is used by the HTTP handlers to surface the active
// settings in /api/serial-bridge/sessions, so keeping our local view
// in sync matters even when the kernel-level set fails.
func (p *iacParser) applyBaud(baud int) error {
	p.sess.mu.Lock()
	p.sess.pub.BaudRate = baud
	dataBits := p.sess.pub.DataBits
	parity := p.sess.pub.Parity
	stopBits := p.sess.pub.StopBits
	p.sess.mu.Unlock()
	return configureTermios(p.sess.serialFD, baud, dataBits, parity, stopBits)
}

func (p *iacParser) applyFraming(dataBits int, parity, stopBits string) error {
	p.sess.mu.Lock()
	p.sess.pub.DataBits = dataBits
	p.sess.pub.Parity = parity
	p.sess.pub.StopBits = stopBits
	baud := p.sess.pub.BaudRate
	p.sess.mu.Unlock()
	return configureTermios(p.sess.serialFD, baud, dataBits, parity, stopBits)
}

func (p *iacParser) dataBits() int {
	p.sess.mu.Lock()
	defer p.sess.mu.Unlock()
	return p.sess.pub.DataBits
}

func (p *iacParser) parity() string {
	p.sess.mu.Lock()
	defer p.sess.mu.Unlock()
	return p.sess.pub.Parity
}

func (p *iacParser) stopBits() string {
	p.sess.mu.Lock()
	defer p.sess.mu.Unlock()
	return p.sess.pub.StopBits
}

// replyBaud emits an IAC SB COM-PORT-OPTION SET-BAUDRATE-REPLY <4 bytes>
// IAC SE. Reply codes are subCmd + 100.
func (p *iacParser) replyBaud() []byte {
	p.sess.mu.Lock()
	baud := uint32(p.sess.pub.BaudRate)
	p.sess.mu.Unlock()
	out := make([]byte, 0, 11)
	out = append(out, iac, iacSB, optComPort, cpcSetBaudRate+100)
	out = append(out, byte(baud>>24), byte(baud>>16), byte(baud>>8), byte(baud))
	out = append(out, iac, iacSE)
	return out
}

func (p *iacParser) replyFraming(subCmd byte) []byte {
	var val byte
	switch subCmd {
	case cpcSetDataSize:
		val = byte(p.dataBits())
	case cpcSetParity:
		val = encodeParity(p.parity())
	case cpcSetStopSize:
		val = encodeStopSize(p.stopBits())
	}
	return []byte{iac, iacSB, optComPort, subCmd + 100, val, iac, iacSE}
}

func decodeParity(b byte) string {
	switch b {
	case 1:
		return "N"
	case 2:
		return "O"
	case 3:
		return "E"
	}
	return ""
}

func encodeParity(p string) byte {
	switch p {
	case "N":
		return 1
	case "O":
		return 2
	case "E":
		return 3
	}
	return 1
}

func decodeStopSize(b byte) string {
	switch b {
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "1.5"
	}
	return ""
}

func encodeStopSize(s string) byte {
	switch s {
	case "1":
		return 1
	case "2":
		return 2
	case "1.5":
		return 3
	}
	return 1
}
