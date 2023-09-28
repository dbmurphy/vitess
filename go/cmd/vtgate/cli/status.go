/*
Copyright 2019 The Vitess Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreedto in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cli

import (
	"vitess.io/vitess/go/vt/discovery"
	"vitess.io/vitess/go/vt/servenv"
	"vitess.io/vitess/go/vt/srvtopo"
	"vitess.io/vitess/go/vt/vtgate"
)

func addStatusParts(vtg *vtgate.VTGate) {
	servenv.AddStatusPart("Executor", vtgate.ExecutorTemplate, func() any {
		return nil
	})
	servenv.AddStatusPart("VSchema", vtgate.VSchemaTemplate, func() any {
		return vtg.VSchemaStats()
	})
	servenv.AddStatusFuncs(srvtopo.StatusFuncs)
	servenv.AddStatusPart("Topology Cache", srvtopo.TopoTemplate, func() any {
		return resilientServer.CacheStatus()
	})
	servenv.AddStatusPart("Gateway Status", vtgate.StatusTemplate, func() any {
		return vtg.GetGatewayCacheStatus()
	})
	servenv.AddStatusPart("Health Check Cache", discovery.HealthCheckTemplate, func() any {
		return vtg.Gateway().TabletsCacheStatus()
	})
}
