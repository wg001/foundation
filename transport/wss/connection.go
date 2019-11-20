/*
	Copyright 2019 Netfoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package wss

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/gorilla/websocket"
	"github.com/netfoundry/ziti-foundation/transport"
	"io"
	"net"
	"time"
)

type WssConnection struct {
	detail    *transport.ConnectionDetail
	websocket *websocket.Conn
	socket    *tls.Conn
}

func (c *WssConnection) Detail() *transport.ConnectionDetail {
	return c.detail
}

func (c *WssConnection) PeerCertificates() []*x509.Certificate {
	return c.socket.ConnectionState().PeerCertificates
}

func (c *WssConnection) Reader() io.Reader {
	return c.socket
}

func (c *WssConnection) Writer() io.Writer {
	return c.socket
}

func (c *WssConnection) Conn() net.Conn {
	return c.socket
}

func (c *WssConnection) SetReadTimeout(t time.Duration) error {
	return c.socket.SetReadDeadline(time.Now().Add(t))
}

func (c *WssConnection) SetWriteTimeout(t time.Duration) error {
	return c.socket.SetWriteDeadline(time.Now().Add(t))
}

func (c *WssConnection) Close() error {
	return c.socket.Close()
}
