package cfgfile

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import (
	"errors"
	"strings"

	"github.com/apache/trafficcontrol/lib/go-atscfg"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/traffic_ops/ort/atstccfg/config"
	"github.com/apache/trafficcontrol/traffic_ops/ort/atstccfg/toreq"
)

func GetConfigFileCDNRegexRemap(cfg config.TCCfg, cdnNameOrID string, fileName string) (string, error) {
	configSuffix := `.config`
	if !strings.HasPrefix(fileName, atscfg.RegexRemapPrefix) || !strings.HasSuffix(fileName, configSuffix) {
		return `{"alerts":[{"level":"error","text":"Error - regex remap file '` + fileName + `' not of the form 'regex_remap_*.config! Please file a bug with Traffic Control, this should never happen."}]}`, config.ErrBadRequest
	}
	dsName := strings.TrimSuffix(strings.TrimPrefix(fileName, atscfg.RegexRemapPrefix), configSuffix)
	if dsName == "" {
		return `{"alerts":[{"level":"error","text":"Error - regex remap file '` + fileName + `' has no delivery service name!"}]}`, config.ErrBadRequest
	}

	cdnName, err := toreq.GetCDNNameFromCDNNameOrID(cfg, cdnNameOrID)
	if err != nil {
		return "", errors.New("getting CDN name from '" + cdnNameOrID + "': " + err.Error())
	}

	toToolName, toURL, err := toreq.GetTOToolNameAndURLFromTO(cfg)
	if err != nil {
		return "", errors.New("getting global parameters: " + err.Error())
	}

	cdn, err := toreq.GetCDN(cfg, cdnName)
	if err != nil {
		return "", errors.New("getting cdn '" + string(cdnName) + "': " + err.Error())
	}

	dses, err := toreq.GetCDNDeliveryServices(cfg, cdn.ID)
	if err != nil {
		return "", errors.New("getting delivery services: " + err.Error())
	}

	// only send the requested DS to atscfg. The atscfg.Make will work correctly even if we send it other DSes, but this will prevent atscfg.DeliveryServicesToCDNDSes from logging errors about AnyMap and Steering DSes without origins.
	ds := tc.DeliveryServiceNullable{}
	for _, dsesDS := range dses {
		if dsesDS.XMLID == nil {
			continue // TODO log?
		}
		if *dsesDS.XMLID != dsName {
			continue
		}
		ds = dsesDS
	}
	if ds.ID == nil {
		return `{"alerts":[{"level":"error","text":"Error - delivery service '` + dsName + `' not found! Do you have a regex_remap_*.config location Parameter for a delivery service that doesn't exist?"}]}`, config.ErrNotFound
	}

	cfgDSes := atscfg.DeliveryServicesToCDNDSes([]tc.DeliveryServiceNullable{ds})

	txt := atscfg.MakeRegexRemapDotConfig(cdnName, toToolName, toURL, fileName, cfgDSes)
	return txt, nil
}
