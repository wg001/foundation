/*
	Copyright NetFoundry, Inc.

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

package channel2

import "github.com/michaelquigley/pfxlog"

// LatencyHandler responds to latency messages with Result messages.
//
type LatencyHandler struct{}

func (h *LatencyHandler) ContentType() int32 {
	return ContentTypeLatencyType
}

func (h *LatencyHandler) HandleReceive(msg *Message, ch Channel) {
	response := NewResult(true, "")
	response.ReplyTo(msg)
	if err := ch.SendWithPriority(response, High); err != nil {
		pfxlog.ContextLogger(ch.Label()).Errorf("error sending latency response (%s)", err)
	}
}
