package tcdata

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
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/apache/trafficcontrol/lib/go-tc"
)

func (r *TCData) CreateTestDeliveryServices(t *testing.T) {
	pl := tc.Parameter{
		ConfigFile: "remap.config",
		Name:       "location",
		Value:      "/remap/config/location/parameter/",
	}
	_, _, err := TOSession.CreateParameter(pl)
	if err != nil {
		t.Errorf("cannot create parameter: %v", err)
	}
	for _, ds := range r.TestData.DeliveryServices {
		_, _, err = TOSession.CreateDeliveryServiceV30(ds)
		if err != nil {
			t.Errorf("could not CREATE delivery service '%s': %v", *ds.XMLID, err)
		}
		if ds.Type == nil {
			continue
		}

		dsIsHTTPOrDNS := ds.Type.IsHTTP() || ds.Type.IsDNS() // exclude any_map and other special types

		if dsIsHTTPOrDNS &&
			ds.Signed == true &&
			ds.SigningAlgorithm != nil &&
			*ds.SigningAlgorithm == tc.SigningAlgorithmURLSig {
			if ds.XMLID == nil {
				t.Fatalf("could not generate delivery service url sig keys: test data had DS with nil xmlId")
			}
			_, err := TOSession.Client.Post(TOSession.URL+TOSession.APIBase()+`/deliveryservices/xmlId/`+*ds.XMLID+`/urlkeys/generate`, "", nil)
			if err != nil {
				t.Fatalf("could not create delivery service '%s' urlsig keys: %v", *ds.XMLID, err)
			}
		}

	}
}

func (r *TCData) DeleteTestDeliveryServices(t *testing.T) {
	dses, _, err := TOSession.GetDeliveryServicesV30WithHdr(nil, nil)
	if err != nil {
		t.Errorf("cannot GET deliveryservices: %v", err)
	}
	for _, testDS := range r.TestData.DeliveryServices {
		var ds tc.DeliveryServiceNullableV30
		found := false
		for _, realDS := range dses {
			if realDS.XMLID != nil && *realDS.XMLID == *testDS.XMLID {
				ds = realDS
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DeliveryService not found in Traffic Ops: %v", *ds.XMLID)
			continue
		}

		delResp, err := TOSession.DeleteDeliveryService(strconv.Itoa(*ds.ID))
		if err != nil {
			t.Errorf("cannot DELETE DeliveryService by ID: %v - %v", err, delResp)
			continue
		}

		// Retrieve the Server to see if it got deleted
		params := url.Values{}
		params.Set("id", strconv.Itoa(*ds.ID))
		foundDS, _, err := TOSession.GetDeliveryServicesV30WithHdr(nil, params)
		if err != nil {
			t.Errorf("Unexpected error deleting Delivery Service '%s': %v", *ds.XMLID, err)
		}
		if len(foundDS) > 0 {
			t.Errorf("expected Delivery Service: %s to be deleted, but %d exist with same ID (#%d)", *ds.XMLID, len(foundDS), *ds.ID)
		}
	}

	// clean up parameter created in CreateTestDeliveryServices()
	params, _, err := TOSession.GetParameterByNameAndConfigFile("location", "remap.config")
	for _, param := range params {
		deleted, _, err := TOSession.DeleteParameterByID(param.ID)
		if err != nil {
			t.Errorf("cannot DELETE parameter by ID (%d): %v - %v", param.ID, err, deleted)
		}
	}
}

func (r *TCData) CreateTestDeliveryServiceServers(t *testing.T) {
	servers, _, err := TOSession.GetServersWithHdr(nil, nil) // (tc.ServersV3Response, toclientlib.ReqInf, error) {
	if err != nil {
		t.Fatalf("could not get servers: %v", err)
	}

	dses, _, err := TOSession.GetDeliveryServicesV30WithHdr(nil, nil)
	if err != nil {
		t.Fatalf("could not get servers: %v", err)
	}

	for _, ds := range dses {
		if ds.ID == nil {
			t.Fatal("ds had nil ID")
		} else if ds.CDNID == nil {
			t.Fatal("ds had nil CDNID")
		}
		if ds.Topology != nil && *ds.Topology != "" {
			continue
		}

		dsIsHTTPOrDNS := ds.Type.IsHTTP() || ds.Type.IsDNS() // exclude any_map and other special types
		if !dsIsHTTPOrDNS {
			continue
		}

		serverIDs := []int{}

		for _, server := range servers.Response {
			if server.ID == nil {
				t.Fatal("server had nil ID")
			} else if server.CDNID == nil {
				t.Fatal("server had nil CDNID")
			}
			if *ds.CDNID != *server.CDNID {
				continue
			}
			isCache := strings.HasPrefix(server.Type, "EDGE") || strings.HasPrefix(server.Type, "MID")
			if !isCache {
				continue
			}
			serverIDs = append(serverIDs, *server.ID)
		}

		_, _, err := TOSession.CreateDeliveryServiceServers(*ds.ID, serverIDs, false)
		if err != nil {
			t.Fatal("creating deliveryserviceserver: %v", err)
		}
	}
}

func (r *TCData) DeleteTestDeliveryServiceServers(t *testing.T) {
	// TODO figure out how to clean up DSS, when the API won't let you.

	// dses, _, err := TOSession.GetDeliveryServicesV30WithHdr(nil, nil)
	// if err != nil {
	// 	t.Fatalf("could not get servers: %v", err)
	// }

	// for _, ds := range dses {
	// 	if ds.ID == nil {
	// 		t.Fatal("ds had nil ID")
	// 	}

	// 	_, _, err := TOSession.CreateDeliveryServiceServers(*ds.ID, []int{}, true)
	// 	if err != nil {
	// 		t.Fatal("creating deliveryserviceserver: %v", err)
	// 	}
	// }
}
