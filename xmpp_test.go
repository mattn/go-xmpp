package xmpp

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

type localAddr struct{}

func (a *localAddr) Network() string {
	return "tcp"
}

func (addr *localAddr) String() string {
	return "localhost:5222"
}

type testConn struct {
	*bytes.Buffer
}

func tConnect(s string) net.Conn {
	var conn testConn
	conn.Buffer = bytes.NewBufferString(s)
	return &conn
}

func (*testConn) Close() error {
	return nil
}

func (*testConn) LocalAddr() net.Addr {
	return &localAddr{}
}

func (*testConn) RemoteAddr() net.Addr {
	return &localAddr{}
}

func (*testConn) SetDeadline(time.Time) error {
	return nil
}

func (*testConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*testConn) SetWriteDeadline(time.Time) error {
	return nil
}

var text = strings.TrimSpace(`
<message xmlns="jabber:client" id="3" type="error" to="123456789@gcm.googleapis.com/ABC">
	<gcm xmlns="google:mobile:data">
		{"random": "&lt;text&gt;"}
	</gcm>
	<error code="400" type="modify">
		<bad-request xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"/>
		<text xmlns="urn:ietf:params:xml:ns:xmpp-stanzas">
			InvalidJson: JSON_PARSING_ERROR : Missing Required Field: message_id\n
		</text>
	</error>
</message>
`)

func TestStanzaError(t *testing.T) {
	var c Client
	c.conn = tConnect(text)
	c.p = xml.NewDecoder(c.conn)
	v, err := c.Recv()
	if err != nil {
		t.Fatalf("Recv() = %v", err)
	}

	chat := Chat{
		Type: "error",
		Other: []string{
			"\n\t\t{\"random\": \"<text>\"}\n\t",
			"\n\t\t\n\t\t\n\t",
		},
		OtherElem: []XMLElement{
			XMLElement{
				XMLName:  xml.Name{Space: "google:mobile:data", Local: "gcm"},
				InnerXML: "\n\t\t{\"random\": \"&lt;text&gt;\"}\n\t",
			},
			XMLElement{
				XMLName: xml.Name{Space: "jabber:client", Local: "error"},
				InnerXML: `
		<bad-request xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"/>
		<text xmlns="urn:ietf:params:xml:ns:xmpp-stanzas">
			InvalidJson: JSON_PARSING_ERROR : Missing Required Field: message_id\n
		</text>
	`,
			},
		},
	}
	if !reflect.DeepEqual(v, chat) {
		t.Errorf("Recv() = %#v; want %#v", v, chat)
	}
}

func TestEOFError(t *testing.T) {
	var c Client
	c.conn = tConnect("")
	c.p = xml.NewDecoder(c.conn)
	_, err := c.Recv()
	if err != io.EOF {
		t.Errorf("Recv() did not return io.EOF on end of input stream")
	}
}

func TestMechanism(t *testing.T) {
	readToken := func(r io.Reader) <-chan string {
		rCh := make(chan string, 10)
		go func() {
			dec := xml.NewDecoder(r)
			for {
				nextToken, err := dec.Token()
				if err != nil {
					rCh <- err.Error()
					break
				}
				switch nextToken.(type) {
				case xml.StartElement:
					buf := new(bytes.Buffer)
					enc := xml.NewEncoder(buf)
					err = enc.EncodeToken(nextToken)
					if err != nil {
						rCh <- err.Error()
						break
					}
					err = enc.Flush()
					if err != nil {
						rCh <- err.Error()
						break
					}
					rCh <- buf.String()
				}
			}
			close(rCh)
		}()

		return rCh
	}

	for idx, tc := range []struct {
		ExpectedType string
		Response     string
		AuthExternal bool
	}{
		// AuthExternal: true
		{
			"EXTERNAL",
			`<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism><mechanism>PLAIN</mechanism><mechanism>X-OAUTH2</mechanism></mechanisms><register xmlns='http://jabber.org/features/iq-register'/></stream:features>`,
			true,
		},
		// AuthExternal: false
		{
			"PLAIN",
			`<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism><mechanism>PLAIN</mechanism><mechanism>X-OAUTH2</mechanism></mechanisms><register xmlns='http://jabber.org/features/iq-register'/></stream:features>`,
			false,
		},
		// Server doesn't support EXTERNAL
		{
			"PLAIN",
			`<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>X-OAUTH2</mechanism></mechanisms><register xmlns='http://jabber.org/features/iq-register'/></stream:features>`,
			true,
		},
	} {
		t.Run(fmt.Sprintf("Case %d", idx+1), func(t *testing.T) {

			var c Client
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()

			c.conn = client
			c.p = xml.NewDecoder(c.conn)

			go func() {
				// first response
				fmt.Fprintf(server, `<?xml version='1.0'?><stream:stream id='16334887770442657903' version='1.0' xml:lang='en' xmlns:stream='http://etherx.jabber.org/streams' from='client' xmlns='jabber:client'>`)
				// mechanism
				fmt.Fprintf(server, tc.Response)
			}()

			go func() {
				c.init(&Options{
					User:                         "user@domain",
					Password:                     "invalid",
					InsecureAllowUnencryptedAuth: true,
					AuthExternal:                 tc.AuthExternal,
				})
			}()

			req := readToken(server)

			// skip first
			select {
			case <-req:
			case <-time.After(10 * time.Millisecond):
				t.Fatal("Did not receive first response")
			}

			select {
			case mechanismResp := <-req:
				if expected, got := fmt.Sprintf(`<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" xmlns="urn:ietf:params:xml:ns:xmpp-sasl" mechanism="%s">`, tc.ExpectedType), mechanismResp; expected != got {
					t.Errorf("Invalid mechanism response, expected %s, got %s", expected, got)
				}
			case <-time.After(10 * time.Millisecond):
				t.Fatal("Did not receive mechanism response")
			}
		})
	}
}
