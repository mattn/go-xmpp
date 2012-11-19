// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TODO(rsc):
//	More precise error handling.
//	Presence functionality.
// TODO(mattn):
//  Add proxy authentication.

// Package xmpp implements a simple Google Talk client
// using the XMPP protocol described in RFC 3920 and RFC 3921.
package xmpp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	nsStream = "http://etherx.jabber.org/streams"
	nsTLS    = "urn:ietf:params:xml:ns:xmpp-tls"
	nsSASL   = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind   = "urn:ietf:params:xml:ns:xmpp-bind"
	nsClient = "jabber:client"
)

var DefaultConfig struct {
	TLS   tls.Config
	Debug struct {
		R io.Writer // all received data will be copied to this writer
		W io.Writer // all sent data will be copied to this writer
	}
}

type Client struct {
	tls *tls.Conn // connection to server
	jid string    // Jabber ID for our connection
	dec *xml.Decoder
	enc *xml.Encoder
}

// NewClient creates a new connection to a host given as "hostname" or "hostname:port".
// If host is not specified, the  DNS SRV should be used to find the host from the domainpart of the JID.
// Default the port to 5222.
func NewClient(host, user, passwd string) (*Client, error) {
	addr := host

	if strings.TrimSpace(host) == "" {
		a := strings.SplitN(user, "@", 2)
		if len(a) == 2 {
			host = a[1]
		}
	}
	a := strings.SplitN(host, ":", 2)
	if len(a) == 1 {
		host += ":5222"
	}
	proxy := os.Getenv("HTTP_PROXY")
	if proxy == "" {
		proxy = os.Getenv("http_proxy")
	}
	if proxy != "" {
		url, err := url.Parse(proxy)
		if err == nil {
			addr = url.Host
		}
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	if proxy != "" {
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\n", host)
		fmt.Fprintf(c, "Host: %s\r\n", host)
		fmt.Fprintf(c, "\r\n")
		br := bufio.NewReader(c)
		req, _ := http.NewRequest("CONNECT", host, nil)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			f := strings.SplitN(resp.Status, " ", 2)
			return nil, errors.New(f[1])
		}
	}

	tlsconn := tls.Client(c, &DefaultConfig.TLS)
	if err = tlsconn.Handshake(); err != nil {
		return nil, err
	}

	if strings.LastIndex(host, ":") > 0 {
		host = host[:strings.LastIndex(host, ":")]
	}
	if err = tlsconn.VerifyHostname(host); err != nil {
		return nil, err
	}

	client := new(Client)
	client.tls = tlsconn
	if err := client.init(user, passwd); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func (c *Client) Close() error {
	return c.tls.Close()
}

func (c *Client) init(user, passwd string) error {
	if DefaultConfig.Debug.R != nil {
		c.dec = xml.NewDecoder(io.TeeReader(c.tls, DefaultConfig.Debug.R))
	} else {
		c.dec = xml.NewDecoder(c.tls)
	}
	if DefaultConfig.Debug.W != nil {
		c.enc = xml.NewEncoder(io.MultiWriter(DefaultConfig.Debug.W, c.tls))
	} else {
		c.enc = xml.NewEncoder(c.tls)
	}

	a := strings.SplitN(user, "@", 2)
	if len(a) != 2 {
		return errors.New("xmpp: invalid username (want user@domain): " + user)
	}
	user = a[0]
	domain := a[1]

	// Declare intent to be a jabber client.
	fmt.Fprintf(c.tls, "<?xml version='1.0'?>\n"+
		"<stream:stream to='%s' xmlns='%s'\n"+
		" xmlns:stream='%s' version='1.0'>\n",
		xmlEscape(domain), nsClient, nsStream)

	// Server should respond with a stream opening.
	se, err := nextStart(c.dec)
	if err != nil {
		return err
	}
	if se.Name.Space != nsStream || se.Name.Local != "stream" {
		return errors.New("xmpp: expected <stream> but got <" + se.Name.Local + "> in " + se.Name.Space)
	}

	// Now we're in the stream and can use Unmarshal.
	// Next message should be <features> to tell us authentication options.
	// See section 4.6 in RFC 3920.
	var f streamFeatures
	if err = c.dec.DecodeElement(&f, nil); err != nil {
		return errors.New("unmarshal <features>: " + err.Error())
	}
	havePlain := false
	for _, m := range f.Mechanisms.Mechanism {
		if m == "PLAIN" {
			havePlain = true
			break
		}
	}
	if !havePlain {
		return errors.New(fmt.Sprintf("PLAIN authentication is not an option: %v", f.Mechanisms.Mechanism))
	}

	// Plain authentication: send base64-encoded \x00 user \x00 password.
	raw := "\x00" + user + "\x00" + passwd
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(enc, []byte(raw))
	fmt.Fprintf(c.tls, "<auth xmlns='%s' mechanism='PLAIN'>%s</auth>\n",
		nsSASL, enc)

	// Next message should be either success or failure.
	name, val, err := next(c.dec)
	switch v := val.(type) {
	case *saslSuccess:
	case *saslFailure:
		// v.Any is type of sub-element in failure,
		// which gives a description of what failed.
		return errors.New("auth failure: " + v.Any.Local)
	default:
		return errors.New("expected <success> or <failure>, got <" + name.Local + "> in " + name.Space)
	}

	// Now that we're authenticated, we're supposed to start the stream over again.
	// Declare intent to be a jabber client.
	fmt.Fprintf(c.tls, "<stream:stream to='%s' xmlns='%s'\n"+
		" xmlns:stream='%s' version='1.0'>\n",
		xmlEscape(domain), nsClient, nsStream)

	// Here comes another <stream> and <features>.
	se, err = nextStart(c.dec)
	if err != nil {
		return err
	}
	if se.Name.Space != nsStream || se.Name.Local != "stream" {
		return errors.New("expected <stream>, got <" + se.Name.Local + "> in " + se.Name.Space)
	}
	if err = c.dec.DecodeElement(&f, nil); err != nil {
		// TODO: often stream stop.
		//return os.NewError("unmarshal <features>: " + err.String())
	}

	// Send IQ message asking to bind to the local user name.
	fmt.Fprintf(c.tls, "<iq type='set' id='x'><bind xmlns='%s'/></iq>\n", nsBind)
	var iq clientIQ
	if err = c.dec.DecodeElement(&iq, nil); err != nil {
		return errors.New("unmarshal <iq>: " + err.Error())
	}
	if &iq.Bind == nil {
		return errors.New("<iq> result missing <bind>")
	}
	c.jid = iq.Bind.Jid // our local id

	// We're connected and can now receive and send messages.
	fmt.Fprintf(c.tls, "<presence xml:lang='en'><show>xa</show><status>I for one welcome our new codebot overlords.</status></presence>")
	return nil
}

// Recv waits until the next *Message or *Presence is received.
func (c *Client) Recv() (event interface{}, err error) {
	for {
		_, val, err := next(c.dec)
		if err != nil {
			return nil, err
		}
		if v, ok := val.(*Message); ok {
			return v, nil
		}
		if v, ok := val.(*Presence); ok {
			return v, nil
		}
		fmt.Println(val)
	}
	panic("unreachable")
}

// Send sends an XML encoded event.
func (c *Client) Send(v interface{}) error {
	err := c.enc.Encode(v)
	if err != nil {
		return err
	}
	return c.enc.Flush() //TODO(swd): is this Flush necessary?
}

// RFC 3920  C.1  Streams name space

type streamFeatures struct {
	XMLName    xml.Name `xml:"http://etherx.jabber.org/streams features"`
	StartTLS   tlsStartTLS
	Mechanisms saslMechanisms
	Bind       bindBind
	Session    bool
}

type streamError struct {
	XMLName xml.Name `xml:"http://etherx.jabber.org/streams error"`
	Any     xml.Name
	Text    string
}

// RFC 3920  C.3  TLS name space

type tlsStartTLS struct {
	XMLName  xml.Name `xml:":ietf:params:xml:ns:xmpp-tls starttls"`
	Required bool
}

type tlsProceed struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls proceed"`
}

type tlsFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls failure"`
}

// RFC 3920  C.4  SASL name space

type saslMechanisms struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl mechanisms"`
	Mechanism []string `xml:"mechanism"`
}

type saslAuth struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
	Mechanism string   `xml:",attr"`
}

type saslChallenge string

type saslResponse string

type saslAbort struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl abort"`
}

type saslSuccess struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl success"`
}

type saslFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl failure"`
	Any     xml.Name
}

// RFC 3920  C.5  Resource binding name space

type bindBind struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string
	Jid      string
}

// RFC 3921  B.1  jabber:client

type Message struct {
	XMLName xml.Name `xml:"jabber:client message"`
	From    string   `xml:"from,attr"`
	Id      string   `xml:"id,attr"`
	To      string   `xml:"to,attr"`
	Type    string   `xml:"type,attr"` // chat, error, groupchat, headline, or normal

	// These should technically be []clientText,
	// but string is much more convenient.
	Subject string `xml:"subject"`
	Body    string `xml:"body"`
	Thread  string `xml:"thread"`
}

type clientText struct {
	Lang string `xml:",attr"`
	Body string `xml:"chardata"`
}

type Presence struct {
	XMLName xml.Name `xml:"jabber:client presence"`
	From    string   `xml:"from,attr"`
	Id      string   `xml:"id,attr"`
	To      string   `xml:"to,attr"`
	Type    string   `xml:"type,attr"` // error, probe, subscribe, subscribed, unavailable, unsubscribe, unsubscribed
	Lang    string   `xml:"lang,attr"`

	Show     string `xml:"show,attr"`   // away, chat, dnd, xa
	Status   string `xml:"status,attr"` // sb []clientText
	Priority string `xml:"priority,attr"`
	Error    *clientError
}

type clientIQ struct { // info/query
	XMLName xml.Name `xml:"jabber:client iq"`
	From    string   `xml:",attr"`
	Id      string   `xml:",attr"`
	To      string   `xml:",attr"`
	Type    string   `xml:",attr"` // error, get, result, set
	Error   clientError
	Bind    bindBind
}

type clientError struct {
	XMLName xml.Name `xml:"jabber:client error"`
	Code    string   `xml:",attr"`
	Type    string   `xml:",attr"`
	Any     xml.Name
	Text    string
}

// Scan XML token stream to find next StartElement.
func nextStart(p *xml.Decoder) (xml.StartElement, error) {
	for {
		t, err := p.Token()
		if err != nil {
			log.Fatal("token", err)
		}
		switch t := t.(type) {
		case xml.StartElement:
			return t, nil
		}
	}
	panic("unreachable")
}

// Scan XML token stream for next element and save into val.
// If val == nil, allocate new element based on proto map.
// Either way, return val.
func next(p *xml.Decoder) (xml.Name, interface{}, error) {
	// Read start element to find out what type we want.
	se, err := nextStart(p)
	if err != nil {
		return xml.Name{}, nil, err
	}

	// Put it in an interface and allocate one.
	var nv interface{}
	switch se.Name.Space + " " + se.Name.Local {
	case nsStream + " features":
		nv = &streamFeatures{}
	case nsStream + " error":
		nv = &streamError{}
	case nsTLS + " starttls":
		nv = &tlsStartTLS{}
	case nsTLS + " proceed":
		nv = &tlsProceed{}
	case nsTLS + " failure":
		nv = &tlsFailure{}
	case nsSASL + " mechanisms":
		nv = &saslMechanisms{}
	case nsSASL + " challenge":
		nv = ""
	case nsSASL + " response":
		nv = ""
	case nsSASL + " abort":
		nv = &saslAbort{}
	case nsSASL + " success":
		nv = &saslSuccess{}
	case nsSASL + " failure":
		nv = &saslFailure{}
	case nsBind + " bind":
		nv = &bindBind{}
	case nsClient + " message":
		nv = &Message{}
	case nsClient + " presence":
		nv = &Presence{}
	case nsClient + " iq":
		nv = &clientIQ{}
	case nsClient + " error":
		nv = &clientError{}
	default:
		return xml.Name{}, nil, errors.New("unexpected XMPP message " +
			se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err = p.DecodeElement(nv, &se); err != nil {
		return xml.Name{}, nil, err
	}
	return se.Name, nv, err
}

var xmlSpecial = map[byte]string{
	'<':  "&lt;",
	'>':  "&gt;",
	'"':  "&quot;",
	'\'': "&apos;",
	'&':  "&amp;",
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if s, ok := xmlSpecial[c]; ok {
			b.WriteString(s)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
