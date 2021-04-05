package orttest

/*
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/traffic_ops_ort/testing/ort-tests/tcdata"
	"github.com/apache/trafficcontrol/traffic_ops_ort/testing/ort-tests/util"
)

func TestURLSigFiles(t *testing.T) {
	t.Log("------------- Starting TestURLSigFiles ---------------")
	tcd.WithObjs(t, []tcdata.TCObj{
		tcdata.CDNs, tcdata.Types, tcdata.Tenants, tcdata.Parameters,
		tcdata.Profiles, tcdata.ProfileParameters, tcdata.Statuses,
		tcdata.Divisions, tcdata.Regions, tcdata.PhysLocations,
		tcdata.CacheGroups, tcdata.Servers, tcdata.Topologies,
		tcdata.DeliveryServices, tcdata.DeliveryServiceServers}, func() {

		if err := t3c_update("atlanta-edge-03", "badass"); err != nil {
			t.Fatalf("running t3c: %v", err)
		}

		toClient := tcdata.TOSession
		dses, _, err := toClient.GetDeliveryServicesV30WithHdr(nil, nil)
		if err != nil {
			t.Fatalf("cannot GET deliveryservices: %v", err)
		}

		urlSigDS := tc.DeliveryServiceNullableV30{}
		for _, ds := range dses {
			if ds.XMLID == nil {
				continue
			}
			if ds.Type == nil {
				continue
			}
			dsIsHTTPOrDNS := ds.Type.IsHTTP() || ds.Type.IsDNS() // exclude any_map and other special types

			if !dsIsHTTPOrDNS ||
				!ds.Signed ||
				ds.SigningAlgorithm == nil ||
				*ds.SigningAlgorithm != tc.SigningAlgorithmURLSig {
				continue
			}
			urlSigDS = ds
			break
		}
		if urlSigDS.XMLID == nil {
			t.Fatal("deliveryservices had no url sig ds, cannot test url sig")
		}
		urlSigKeys, _, err := toClient.GetDeliveryServiceURLSigKeys(*urlSigDS.XMLID)
		if err != nil {
			t.Fatalf("getting ds '%v' url sig keys: %v", *urlSigDS.XMLID, err)
		}

		if len(urlSigKeys) < 3 {
			t.Fatalf("ds '%v' url sig keys expected > 2, actual len %v %+v", *urlSigDS.XMLID, len(urlSigKeys), urlSigKeys)
		}

		urlSigFileName := test_config_dir + "/url_sig_" + *urlSigDS.XMLID + ".config"
		if !util.FileExists(urlSigFileName) {
			t.Fatalf("missing the expected config file '%v'", urlSigFileName)
		}

		bts, err := ioutil.ReadFile(urlSigFileName)
		if err != nil {
			t.Fatalf("reading config file '%v': %v", urlSigFileName, err)
		}

		urlSigFileStr := string(bts)
		urlSigFileStr = strings.Replace(urlSigFileStr, " ", "", -1)

		for key, val := range urlSigKeys {
			keyExpr := key + "=" + val
			if !strings.Contains(urlSigFileStr, keyExpr) {
				t.Errorf("file '%v' expected '%v' actual '%v'", urlSigFileName, keyExpr, urlSigFileStr)
			}
		}

		t.Log("------------- End of TestURLSigFiles test ---------------")
	})
	t.Log("------------- End of TestURLSigFiles ---------------")
}
