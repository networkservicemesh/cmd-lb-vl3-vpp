// Copyright (c) 2023 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config provides methods to get configuration parameters from environment variables
package config

import (
	"net/url"
	"time"

	"github.com/networkservicemesh/govpp/binapi/ip_types"

	"github.com/pkg/errors"

	"github.com/kelseyhightower/envconfig"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name                  string        `default:"cmd-lb-vl3-vpp" desc:"Name of Endpoint"`
	DialTimeout           time.Duration `default:"5s" desc:"timeout to dial NSMgr" split_words:"true"`
	RequestTimeout        time.Duration `default:"15s" desc:"timeout to request NSE" split_words:"true"`
	ConnectTo             url.URL       `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime      time.Duration `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	NetworkServices       []url.URL     `default:"" desc:"A list of Network Service Requests" split_words:"true"`
	LogLevel              string        `default:"INFO" desc:"Log level" split_words:"true"`
	OpenTelemetryEndpoint string        `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint"`
	MetricsExportInterval time.Duration `default:"10s" desc:"interval between mertics exports" split_words:"true"`

	Port       uint16            `default:"" desc:"TCP/UDP service port" split_words:"true"`
	TargetPort uint16            `default:"" desc:"TCP/UDP target port" split_words:"true"`
	Protocol   Protocol          `default:"TCP" desc:"TCP or UDP protocol" split_words:"true"`
	Selector   map[string]string `default:"" desc:"labels for the load balancer selector labels" split_words:"true"`
}

// Process - parses the config
func (c *Config) Process() error {
	if err := envconfig.Usage("nsm", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig")
	}
	if err := envconfig.Process("nsm", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig")
	}

	if c.Port == 0 {
		return errors.New("Port cannot be empty")
	}
	if c.TargetPort == 0 {
		c.TargetPort = c.Port
	}
	return nil
}

// Protocol represents ip_types.IPProto
type Protocol ip_types.IPProto

// UnmarshalBinary unmarshal protocol name
func (p *Protocol) UnmarshalBinary(bytes []byte) error {
	text := string(bytes)
	proto, ok := ip_types.IPProto_value["IP_API_PROTO_"+text]
	if !ok {
		return errors.New("unknown protocol")
	}
	*p = Protocol(proto)
	if ip_types.IPProto(*p) != ip_types.IP_API_PROTO_TCP && ip_types.IPProto(*p) != ip_types.IP_API_PROTO_UDP {
		return errors.New("protocol is not supported")
	}
	return nil
}
