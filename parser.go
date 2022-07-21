package iptables

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// Log represents the parsed iptables log entry.
type Log struct {
	Timestamp              string  `json:"timestamp"`
	Hostname               string  `json:"hostname"`
	KernelTimestamp        float64 `json:"kernelTimestamp"`
	Prefix                 string  `json:"prefix"`
	InputInterface         string  `json:"inputInterface"`
	OutputInterface        string  `json:"outputInterface"`
	MACAddress             string  `json:"macAddress"`
	Source                 string  `json:"source"`
	Destination            string  `json:"destination"`
	Length                 uint64  `json:"length"`
	ToS                    uint8   `json:"tos"`
	Precedence             uint8   `json:"precedence"`
	TTL                    uint64  `json:"ttl"`
	ID                     uint64  `json:"id"`
	CongestionExperienced  bool    `json:"congestionExperienced"`
	DoNotFragment          bool    `json:"doNotFragment"`
	MoreFragmentsFollowing bool    `json:"moreFragmentsFollowing"`
	Frag                   int64   `json:"frag"`
	IPOptions              string  `json:"ipOptions"`
	Protocol               string  `json:"protocol"`
	Type                   int64   `json:"type"`
	Code                   int64   `json:"code"`
	SourcePort             uint16  `json:"sourcePort"`
	DestinationPort        uint16  `json:"destinationPort"`
	Sequence               uint64  `json:"sequence"`
	AckSequence            uint64  `json:"ackSequence"`
	WindowSize             uint64  `json:"windowSize"`
	Res                    uint64  `json:"res"`
	Urgent                 bool    `json:"urgent"`
	Ack                    bool    `json:"ack"`
	Push                   bool    `json:"push"`
	Reset                  bool    `json:"reset"`
	Syn                    bool    `json:"syn"`
	Fin                    bool    `json:"fin"`
	Urgp                   uint64  `json:"urgp"`
	TCPOption              string  `json:"tcpOption"`
}

var re = regexp.MustCompile(`^(?P<timestamp>.+)\s+(?P<hostname>\S+)\s+kernel:\s+\[\s*(?P<kernel_timestamp>[^]]+)]\s+(?:(?P<prefix>.+)\s+)?IN=(\S*)\s+OUT=(\S*)\s+(?:MAC=(\S*)\s+)?SRC=(\S*)\s+DST=(\S*)\s+LEN=(\d*)\s+TOS=(?:0x(\S+))?\s+PREC=(?:0x(\S+))?\s+TTL=(\d*)\s+ID=(\d*)\s+(CE\s+)?(DF\s+)?(MF\s+)?(?:FRAG=(\d*)\s+)?(?:OPT \((.+)\)\s+)?PROTO=(\S+)(?:\s+TYPE=(\d+))?(?:\s+CODE=(\d+))?(?:\s+SPT=(\d*))?(?:\s+DPT=(\d*))?(?:\s+SEQ=(\d*))?(?:\s+ACK=(\d*))?(?:\s+WINDOW=(\d*))?(?:\s+RES=0x(\S*))?(\s+URG)?(\s+ACK)?(\s+PSH)?(\s+RST)?(\s+SYN)?(\s+FIN)?(?:\s+URGP=(\d*))?(?:\s+OPT \((.*)\))?`)

var (
	// ErrLogFormatUnmatched is an error that occurs when it cannot parse the given log line.
	ErrLogFormatUnmatched = errors.New("given log text is not matched with the log format")
	// ErrStringToNumberConversionFailed is an error that occurs when it cannot convert a stringy number field into number.
	ErrStringToNumberConversionFailed = errors.New("failed to convert a string field to number")
)

// Parse parses an iptables line.
// This function might return the two types of error: ErrLogFormatUnmatched or ErrStringToNumberConversionFailed.
func Parse(line string) (*Log, error) {
	submatch := re.FindStringSubmatch(line)
	if len(submatch) <= 0 {
		return nil, ErrLogFormatUnmatched
	}

	kernelTimestamp, err := strconv.ParseFloat(submatch[3], 64)
	if err != nil {
		return nil, fmt.Errorf("%s; field = kernel-timestamp: %w", err, ErrStringToNumberConversionFailed)
	}

	l, err := strconv.ParseInt(submatch[10], 10, 64)
	if err != nil && submatch[10] != "" {
		return nil, fmt.Errorf("%s; field = len: %w", err, ErrStringToNumberConversionFailed)
	}

	tos, err := strconv.ParseInt(submatch[11], 16, 64)
	if err != nil && submatch[11] != "" {
		return nil, fmt.Errorf("%s; field = tos: %w", err, ErrStringToNumberConversionFailed)
	}

	prec, err := strconv.ParseInt(submatch[12], 16, 64)
	if err != nil && submatch[12] != "" {
		return nil, fmt.Errorf("%s; field = prec: %w", err, ErrStringToNumberConversionFailed)
	}

	ttl, err := strconv.ParseInt(submatch[13], 10, 64)
	if err != nil && submatch[13] != "" {
		return nil, fmt.Errorf("%s; field = ttl: %w", err, ErrStringToNumberConversionFailed)
	}

	id, err := strconv.ParseInt(submatch[14], 10, 64)
	if err != nil && submatch[14] != "" {
		return nil, fmt.Errorf("%s; field = id: %w", err, ErrStringToNumberConversionFailed)
	}

	frag, err := strconv.ParseInt(submatch[18], 10, 64)
	if err != nil && submatch[18] != "" {
		return nil, fmt.Errorf("%s; field = frag: %w", err, ErrStringToNumberConversionFailed)
	}

	typ, err := strconv.ParseInt(submatch[21], 10, 64)
	if err != nil && submatch[21] != "" {
		return nil, fmt.Errorf("%s; field = type: %w", err, ErrStringToNumberConversionFailed)
	}

	code, err := strconv.ParseInt(submatch[22], 10, 64)
	if err != nil && submatch[22] != "" {
		return nil, fmt.Errorf("%s; field = code: %w", err, ErrStringToNumberConversionFailed)
	}

	sourcePort, err := strconv.ParseInt(submatch[23], 10, 64)
	if err != nil && submatch[23] != "" {
		return nil, fmt.Errorf("%s; field = spt: %w", err, ErrStringToNumberConversionFailed)
	}

	destinationPort, err := strconv.ParseInt(submatch[24], 10, 64)
	if err != nil && submatch[24] != "" {
		return nil, fmt.Errorf("%s; field = dpt: %w", err, ErrStringToNumberConversionFailed)
	}

	sequence, err := strconv.ParseInt(submatch[25], 10, 64)
	if err != nil && submatch[25] != "" {
		return nil, fmt.Errorf("%s; field = seq: %w", err, ErrStringToNumberConversionFailed)
	}

	ack, err := strconv.ParseInt(submatch[26], 10, 64)
	if err != nil && submatch[26] != "" {
		return nil, fmt.Errorf("%s; field = ack: %w", err, ErrStringToNumberConversionFailed)
	}

	window, err := strconv.ParseInt(submatch[27], 10, 64)
	if err != nil && submatch[27] != "" {
		return nil, fmt.Errorf("%s; field = window: %w", err, ErrStringToNumberConversionFailed)
	}

	res, err := strconv.ParseInt(submatch[28], 16, 64)
	if err != nil && submatch[28] != "" {
		return nil, fmt.Errorf("%s; field = res: %w", err, ErrStringToNumberConversionFailed)
	}

	urgp, err := strconv.ParseInt(submatch[35], 10, 64)
	if err != nil && submatch[35] != "" {
		return nil, fmt.Errorf("%s; field = urgp: %w", err, ErrStringToNumberConversionFailed)
	}

	return &Log{
		Timestamp:              submatch[1],
		Hostname:               submatch[2],
		KernelTimestamp:        kernelTimestamp,
		Prefix:                 submatch[4],
		InputInterface:         submatch[5],
		OutputInterface:        submatch[6],
		MACAddress:             submatch[7],
		Source:                 submatch[8],
		Destination:            submatch[9],
		Length:                 uint64(l),
		ToS:                    uint8(tos),
		Precedence:             uint8(prec),
		TTL:                    uint64(ttl),
		ID:                     uint64(id),
		CongestionExperienced:  submatch[15] != "",
		DoNotFragment:          submatch[16] != "",
		MoreFragmentsFollowing: submatch[17] != "",
		Frag:                   frag,
		IPOptions:              submatch[19],
		Protocol:               submatch[20],
		Type:                   typ,
		Code:                   code,
		SourcePort:             uint16(sourcePort),
		DestinationPort:        uint16(destinationPort),
		Sequence:               uint64(sequence),
		AckSequence:            uint64(ack),
		WindowSize:             uint64(window),
		Res:                    uint64(res),
		Urgent:                 submatch[29] != "",
		Ack:                    submatch[30] != "",
		Push:                   submatch[31] != "",
		Reset:                  submatch[32] != "",
		Syn:                    submatch[33] != "",
		Fin:                    submatch[34] != "",
		Urgp:                   uint64(urgp),
		TCPOption:              submatch[36],
	}, nil
}
