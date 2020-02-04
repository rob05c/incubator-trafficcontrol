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
	"strconv"
	"strings"

	"github.com/apache/trafficcontrol/lib/go-atscfg"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/traffic_ops/ort/atstccfg/config"
	"github.com/apache/trafficcontrol/traffic_ops/ort/atstccfg/toreq"
)

func GetConfigFileServerIPAllowDotConfig(cfg config.TCCfg, serverNameOrID string) (string, error) {
	// TODO TOAPI add /servers?cdn=1 query param
	servers, err := toreq.GetServers(cfg)
	if err != nil {
		return "", errors.New("getting servers: " + err.Error())
	}

	server := tc.Server{ID: atscfg.InvalidID}
	if serverID, err := strconv.Atoi(serverNameOrID); err == nil {
		for _, toServer := range servers {
			if toServer.ID == serverID {
				server = toServer
				break
			}
		}
	} else {
		serverName := serverNameOrID
		for _, toServer := range servers {
			if toServer.HostName == serverName {
				server = toServer
				break
			}
		}
	}
	if server.ID == atscfg.InvalidID {
		return "", errors.New("server '" + serverNameOrID + " not found in servers")
	}

	serverName := tc.CacheName(server.HostName)
	serverType := tc.CacheType(server.Type)

	toToolName, toURL, err := toreq.GetTOToolNameAndURLFromTO(cfg)
	if err != nil {
		return "", errors.New("getting global parameters: " + err.Error())
	}

	profileParams, err := toreq.GetProfileParameters(cfg, server.Profile)
	if err != nil {
		return "", errors.New("getting profile '" + server.Profile + "' parameters: " + err.Error())
	}
	if len(profileParams) == 0 {
		// The TO endpoint behind toclient.GetParametersByProfileName returns an empty object with a 200, if the Profile doesn't exist.
		// So we act as though we got a 404 if there are no params, to make ORT behave correctly.
		return "", config.ErrNotFound
	}

	fileParams := map[string][]string{}
	for _, param := range profileParams {
		if param.ConfigFile != atscfg.IPAllowConfigFileName {
			continue
		}
		fileParams[param.Name] = append(fileParams[param.Name], param.Value)
	}

	cacheGroups, err := toreq.GetCacheGroups(cfg)
	if err != nil {
		return "", errors.New("getting cachegroups: " + err.Error())
	}

	cgMap := map[string]tc.CacheGroupNullable{}
	for _, cg := range cacheGroups {
		if cg.Name == nil {
			return "", errors.New("got cachegroup with nil name!'")
		}
		cgMap[*cg.Name] = cg
	}

	serverCG, ok := cgMap[server.Cachegroup]
	if !ok {
		return "", errors.New("server cachegroup not in cachegroups!")
	}

	childCGs := map[string]tc.CacheGroupNullable{}
	for cgName, cg := range cgMap {
		if (cg.ParentName != nil && *cg.ParentName == *serverCG.Name) || (cg.SecondaryParentName != nil && *cg.SecondaryParentName == *serverCG.Name) {
			childCGs[cgName] = cg
		}
	}

	childServers := map[tc.CacheName]atscfg.IPAllowServer{}
	for _, sv := range servers {
		_, ok := childCGs[sv.Cachegroup]
		if ok || (strings.HasPrefix(string(serverType), tc.MidTypePrefix) && string(sv.Type) == tc.MonitorTypeName) {
			childServers[tc.CacheName(sv.HostName)] = atscfg.IPAllowServer{IPAddress: sv.IPAddress, IP6Address: sv.IP6Address}
		}
	}

	txt := atscfg.MakeIPAllowDotConfig(serverName, serverType, toToolName, toURL, fileParams, childServers)
	return txt, nil
}
