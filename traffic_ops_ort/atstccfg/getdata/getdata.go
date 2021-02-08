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

// package getdata gets and posts non-config data from Traffic Ops which is related to config generation and needed by ORT.
// For example, the --get-data, --set-queue-status, and --set-reval-status arguments.
package getdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/apache/trafficcontrol/lib/go-atscfg"
	"github.com/apache/trafficcontrol/lib/go-log"
	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/traffic_ops_ort/atstccfg/cfgfile"
	"github.com/apache/trafficcontrol/traffic_ops_ort/atstccfg/config"
	"github.com/apache/trafficcontrol/traffic_ops_ort/atstccfg/toreq"
	"github.com/apache/trafficcontrol/traffic_ops_ort/atstccfg/toreqnew"
)

func GetDataFuncs() map[string]func(config.TCCfg, io.Writer) error {
	return map[string]func(config.TCCfg, io.Writer) error{
		`update-status`:      WriteServerUpdateStatus,
		`update-status-calc`: WriteServerUpdateStatusCalculated,
		`packages`:           WritePackages,
		`chkconfig`:          WriteChkconfig,
		`system-info`:        WriteSystemInfo,
		`statuses`:           WriteStatuses,
	}
}

func WriteData(cfg config.TCCfg) error {
	log.Infoln("Getting data '" + cfg.GetData + "'")
	dataF, ok := GetDataFuncs()[cfg.GetData]
	if !ok {
		return errors.New("unknown data request '" + cfg.GetData + "'")
	}
	return dataF(cfg, os.Stdout)
}

func SetQueueRevalStatuses(cfg config.TCCfg) error {
	log.Infoln("setting queue reval statuses '" + cfg.SetQueueStatus + "', '" + cfg.SetRevalStatus + "'")
	if cfg.SetQueueStatus == "" || cfg.SetRevalStatus == "" {
		return errors.New("must set both reval and queue status")
	}
	queueStatus := false
	revalStatus := false
	if strings.ToLower(string(cfg.SetQueueStatus[0])) != "f" {
		queueStatus = true
	}
	if strings.ToLower(string(cfg.SetRevalStatus[0])) != "f" {
		revalStatus = true
	}
	return SetUpdateStatus(cfg, tc.CacheName(cfg.CacheHostName), queueStatus, revalStatus)
}

const SystemInfoParamConfigFile = `global`

// WriteSystemInfo writes the "system info" to output.
//
// This is the same info at /api/1.x/system/info, which is actually just all Parameters with the config_file 'global'.
// Note this is different than the more common "global parameters", which usually refers to all Parameters on the Profile named 'GLOBAL'.
//
// This is identical to the /api/1.x/system/info endpoint, except it does not include a '{response: {parameters:' wrapper.
//
func WriteSystemInfo(cfg config.TCCfg, output io.Writer) error {
	paramArr, _, err := cfg.TOClient.GetConfigFileParameters(SystemInfoParamConfigFile)
	if err != nil {
		return errors.New("getting system info parameters: " + err.Error())
	}
	params := map[string]string{}
	for _, param := range paramArr {
		params[param.Name] = param.Value
	}
	if err := json.NewEncoder(output).Encode(params); err != nil {
		return errors.New("encoding system info parameters: " + err.Error())
	}
	return nil
}

// WriteStatuses writes the Traffic Ops statuses to output.
// Note this is identical to /api/1.x/statuses except it omits the '{response:' wrapper.
func WriteStatuses(cfg config.TCCfg, output io.Writer) error {
	statuses, _, err := cfg.TOClient.GetStatuses()
	if err != nil {
		return errors.New("getting statuses: " + err.Error())
	}
	if err := json.NewEncoder(output).Encode(statuses); err != nil {
		return errors.New("encoding statuses: " + err.Error())
	}
	return nil
}

// WriteUpdateStatus writes the Traffic Ops server update status to output.
// Note this is identical to /api/1.x/servers/name/update_status except it omits the '[]' wrapper.
func WriteServerUpdateStatus(cfg config.TCCfg, output io.Writer) error {
	status, _, unsupported, err := cfg.TOClientNew.GetServerUpdateStatus(tc.CacheName(cfg.CacheHostName))
	if err == nil && unsupported {
		log.Warnln("ORT newer than Traffic Ops, falling back to previous API Delivery Services!")
		status, _, err = cfg.TOClient.GetServerUpdateStatus(tc.CacheName(cfg.CacheHostName))
	}
	if err != nil {
		return errors.New("getting server update status: " + err.Error())
	}
	if err := json.NewEncoder(output).Encode(status); err != nil {
		return errors.New("encoding server update status: " + err.Error())
	}
	return nil
}

// WriteUpdateStatusCalculated writes the Traffic Ops server update status to output.
// Note this is identical to /api/1.x/servers/name/update_status except it omits the '[]' wrapper.
//
// This returns the same data as WriteServerUpdateStatus, but calculates from API data endpoints,
// rather than calling the TO endpoint which does the calculation.
func WriteServerUpdateStatusCalculated(cfg config.TCCfg, output io.Writer) error {
	warnings := []string{}

	// TODO only get necessary data.
	toData, _, err := cfgfile.GetTODataUpdateStatus(cfg)
	if err != nil {
		log.Errorln("WriteServerUpdateStatusCalculated getting data from traffic ops: " + err.Error())
		os.Exit(config.ExitCodeErrGeneric)
	}

	if toData.Server.HostName == nil {
		log.Errorln("WriteServerUpdateStatusCalculated server hostname was nil")
		os.Exit(config.ExitCodeErrGeneric)
	} else if toData.Server.ID == nil {
		log.Errorln("WriteServerUpdateStatusCalculated server id was nil")
		os.Exit(config.ExitCodeErrGeneric)
	} else if toData.Server.Status == nil {
		log.Errorln("WriteServerUpdateStatusCalculated server status was nil")
		os.Exit(config.ExitCodeErrGeneric)
	} else if toData.Server.UpdPending == nil {
		log.Errorln("WriteServerUpdateStatusCalculated server updPending was nil")
		os.Exit(config.ExitCodeErrGeneric)
	} else if toData.Server.RevalPending == nil {
		log.Errorln("WriteServerUpdateStatusCalculated server revalPending was nil")
		os.Exit(config.ExitCodeErrGeneric)
	}

	// TODO check Capabilities, exclude parents without the necessary capabilities?

	parents, parentWarns, err := atscfg.GetParents(
		toData.Server,
		toData.Servers,
		toData.DeliveryServices,
		toData.DeliveryServiceServers,
		toData.CacheGroups,
		toData.Topologies,
	)
	warnings = append(warnings, parentWarns...)

	parentPending := false
	parentRevalPending := false
	for _, parent := range parents {
		if parent.UpdPending == nil {
			warnings = append(warnings, "parent had nil updPending, skipping!")
		} else {
			parentPending = parentPending || *parent.UpdPending
		}
		if parent.RevalPending == nil {
			warnings = append(warnings, "parent had nil revalPending, skipping!")
		} else {
			parentRevalPending = parentRevalPending || *parent.RevalPending
		}
		if parentPending && parentRevalPending {
			break
		}
	}

	// TODO avoid getting all data, if server UpdPending and RevalPending are false.
	// If this server isn't pending, nothing will be done, so there's no reason to
	// fetch everything to figure out if the parent is pending.

	// GlobalParams []tc.Parameter

	useRevalParams := cfgfile.FilterParams(toData.GlobalParams, string(tc.GlobalConfigFileName), string(tc.UseRevalPendingParameterName), "", "")
	useRevalPending := len(useRevalParams) > 0 && useRevalParams[0].Value != "" && useRevalParams[0].Value != "0"

	status := tc.ServerUpdateStatus{
		HostName:           *toData.Server.HostName,
		UpdatePending:      *toData.Server.UpdPending,
		RevalPending:       *toData.Server.RevalPending,
		UseRevalPending:    useRevalPending,
		HostId:             *toData.Server.ID,
		Status:             *toData.Server.Status,
		ParentPending:      parentPending,
		ParentRevalPending: parentRevalPending,
	}

	if err := json.NewEncoder(output).Encode(status); err != nil {
		return errors.New("encoding server update status: " + err.Error())
	}
	return nil
}

// WriteORTServerPackages writes the packages for serverName to output.
// Note this is identical to /ort/serverName/packages.
func WritePackages(cfg config.TCCfg, output io.Writer) error {
	packages, err := GetPackages(cfg)
	if err != nil {
		return errors.New("getting ORT server packages: " + err.Error())
	}
	if err := json.NewEncoder(output).Encode(packages); err != nil {
		return errors.New("writing packages: " + err.Error())
	}
	return nil
}

func GetPackages(cfg config.TCCfg) ([]Package, error) {
	server, _, err := cfg.TOClient.GetServerByHostName(string(cfg.CacheHostName))
	if err != nil {
		return nil, errors.New("getting server: " + err.Error())
	} else if server.Profile == nil {
		return nil, errors.New("getting server: nil profile")
	}
	params, _, err := cfg.TOClient.GetServerProfileParameters(*server.Profile)
	if err != nil {
		return nil, errors.New("getting server profile '" + *server.Profile + "' parameters: " + err.Error())
	}
	packages := []Package{}
	for _, param := range params {
		if param.ConfigFile != atscfg.PackagesParamConfigFile {
			continue
		}
		packages = append(packages, Package{Name: param.Name, Version: param.Value})
	}
	return packages, nil
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// WriteChkconfig writes the chkconfig for cfg.CacheHostName to output.
// Note this is identical to /ort/serverName/chkconfig.
func WriteChkconfig(cfg config.TCCfg, output io.Writer) error {
	chkconfig, err := GetChkconfig(cfg)
	if err != nil {
		return errors.New("getting chkconfig: " + err.Error())
	}
	if err := json.NewEncoder(output).Encode(chkconfig); err != nil {
		return errors.New("writing chkconfig: " + err.Error())
	}
	return nil
}

func GetChkconfig(cfg config.TCCfg) ([]ChkConfigEntry, error) {
	server, _, err := cfg.TOClient.GetServerByHostName(string(cfg.CacheHostName))
	if err != nil {
		return nil, errors.New("getting server: " + err.Error())
	} else if server.Profile == nil {
		return nil, errors.New("getting server: nil profile")
	}
	params, _, err := cfg.TOClient.GetServerProfileParameters(*server.Profile)
	if err != nil {
		return nil, errors.New("getting server profile '" + *server.Profile + "' parameters: " + err.Error())
	}
	chkconfig := []ChkConfigEntry{}
	for _, param := range params {
		if param.ConfigFile != atscfg.ChkconfigParamConfigFile {
			continue
		}
		chkconfig = append(chkconfig, ChkConfigEntry{Name: param.Name, Val: param.Value})
	}
	return chkconfig, nil
}

type ChkConfigEntry struct {
	Name string `json:"name"`
	Val  string `json:"value"`
}

// SetUpdateStatus sets the queue and reval status of serverName in Traffic Ops.
func SetUpdateStatus(cfg config.TCCfg, serverName tc.CacheName, queue bool, revalPending bool) error {
	reqInf, err := cfg.TOClientNew.C.SetUpdateServerStatuses(string(serverName), &queue, &revalPending)
	if err != nil && toreqnew.IsUnsupportedErr(err) {
		err = setUpdateStatusLegacy(cfg, serverName, queue, revalPending)
	}
	if err != nil {
		return errors.New("setting update statuses (Traffic Ops '" + toreq.MaybeIPStr(reqInf.RemoteAddr) + "'): " + err.Error())
	}
	return nil
}

// setUpdateStatusLegacy sets the queue and reval status of serverName in Traffic Ops,
// using the legacy pre-2.0 /update endpoint.
func setUpdateStatusLegacy(cfg config.TCCfg, serverName tc.CacheName, queue bool, revalPending bool) error {
	path := `/update/` + string(serverName) + `?updated=` + jsonBoolStr(queue) + `&reval_updated=` + jsonBoolStr(revalPending)
	// C and RawRequest should generally never be used, but the alternatve here is to manually get the cookie and do an http.Get. We need to hit a non-API endpoint, no API endpoint exists for what we need.
	resp, _, err := cfg.TOClient.C.RawRequest(http.MethodPost, path, nil)
	if err != nil {
		return errors.New("setting update statuses: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		bodyBts, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			return fmt.Errorf("Traffic Ops returned %v %v", resp.StatusCode, string(bodyBts))
		}
		return fmt.Errorf("Traffic Ops returned %v (error reading body)", resp.StatusCode)
	}
	return nil
}

func jsonBoolStr(b bool) string {
	if b {
		return `true`
	}
	return `false`
}
