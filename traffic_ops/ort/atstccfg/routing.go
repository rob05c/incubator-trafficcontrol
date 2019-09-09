package main

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
	"net/http"
	"strings"

	"github.com/apache/trafficcontrol/lib/go-log"
)

var scopeConfigFileFuncs = map[string]func(cfg TCCfg, resource string, fileName string) (string, int, error){
	"cdns":     GetConfigFileCDN,
	"servers":  GetConfigFileServer,
	"profiles": GetConfigFileProfile,
}

var ErrNotFound = errors.New("not found")
var ErrBadRequest = errors.New("bad request")

func GetConfigFile(cfg TCCfg) (string, int, error) {
	pathParts := strings.Split(cfg.TOURL.Path, "/")

	log.Infof("GetConfigFile pathParts %++v\n", pathParts)

	if len(pathParts) < 8 {
		log.Infoln("GetConfigFile pathParts < 7, calling TO")
		return GetConfigFileFromTrafficOps(cfg)
	}
	scope := pathParts[3]
	resource := pathParts[4]
	fileName := pathParts[7]

	log.Infoln("GetConfigFile scope '" + scope + "' resource '" + resource + "' fileName '" + fileName + "'")

	if scopeConfigFileFunc, ok := scopeConfigFileFuncs[scope]; ok {
		return scopeConfigFileFunc(cfg, resource, fileName)
	}

	log.Infoln("GetConfigFile unknown scope, calling TO")
	return GetConfigFileFromTrafficOps(cfg)
}

func GetConfigFileCDN(cfg TCCfg, cdnNameOrID string, fileName string) (string, int, error) {
	log.Infoln("GetConfigFileCDN cdn '" + cdnNameOrID + "' fileName '" + fileName + "'")
	return GetConfigFileFromTrafficOps(cfg)
}

func GetConfigFileProfile(cfg TCCfg, profileNameOrID string, fileName string) (string, int, error) {
	log.Infoln("GetConfigFileProfile profile '" + profileNameOrID + "' fileName '" + fileName + "'")

	txt := ""
	err := error(nil)
	if getCfgFunc, ok := ProfileConfigFileFuncs()[fileName]; ok {
		txt, err = getCfgFunc(cfg, profileNameOrID)
	} else if strings.HasPrefix(fileName, "url_sig_") && strings.HasSuffix(fileName, ".config") && len(fileName) > len("url_sig_")+len(".config") {
		txt, err = GetConfigFileProfileURLSigConfig(cfg, profileNameOrID, fileName)
	} else if strings.HasPrefix(fileName, "uri_signing_") && strings.HasSuffix(fileName, ".config") && len(fileName) > len("uri_signing")+len(".config") {
		txt, err = GetConfigFileProfileURISigningConfig(cfg, profileNameOrID, fileName)
	} else {
		txt, err = GetConfigFileProfileUnknownConfig(cfg, profileNameOrID, fileName)
	}

	if err != nil {
		code := ExitCodeErrGeneric
		if err == ErrNotFound {
			code = ExitCodeNotFound
		} else if err == ErrBadRequest {
			code = ExitCodeBadRequest
		}
		return "", code, err
	}
	return txt, ExitCodeSuccess, nil
}

// ConfigFileFuncs returns a map[scope][configFile]configFileFunc.
func ConfigFileFuncs() map[string]map[string]func(cfg TCCfg, serverNameOrID string) (string, error) {
	return map[string]map[string]func(cfg TCCfg, serverNameOrID string) (string, error){
		"cdns":     CDNConfigFileFuncs(),
		"servers":  ServerConfigFileFuncs(),
		"profiles": ProfileConfigFileFuncs(),
	}
}

func CDNConfigFileFuncs() map[string]func(cfg TCCfg, serverNameOrID string) (string, error) {
	return map[string]func(cfg TCCfg, serverNameOrID string) (string, error){}
}

func ProfileConfigFileFuncs() map[string]func(cfg TCCfg, serverNameOrID string) (string, error) {
	return map[string]func(cfg TCCfg, serverNameOrID string) (string, error){
		"12M_facts":           GetConfigFileProfile12MFacts,
		"50-ats.rules":        GetConfigFileProfileATSDotRules,
		"astats.config":       GetConfigFileProfileAstatsDotConfig,
		"cache.config":        GetConfigFileProfileCacheDotConfig,
		"drop_qstring.config": GetConfigFileProfileDropQStringDotConfig,
		"logging.config":      GetConfigFileProfileLoggingDotConfig,
		"logging.yaml":        GetConfigFileProfileLoggingDotYAML,
		"logs_xml.config":     GetConfigFileProfileLogsXMLDotConfig,
		"plugin.config":       GetConfigFileProfilePluginDotConfig,
		"records.config":      GetConfigFileProfileRecordsDotConfig,
		"storage.config":      GetConfigFileProfileStorageDotConfig,
		"sysctl.conf":         GetConfigFileProfileSysCtlDotConf,
		"volume.config":       GetConfigFileProfileVolumeDotConfig,
	}
}

func ServerConfigFileFuncs() map[string]func(cfg TCCfg, serverNameOrID string) (string, error) {
	return map[string]func(cfg TCCfg, serverNameOrID string) (string, error){
		"parent.config": GetConfigFileServerParentDotConfig,
		"remap.config":  GetConfigFileServerRemapDotConfig,
	}
}

func GetConfigFileServer(cfg TCCfg, serverNameOrID string, fileName string) (string, int, error) {
	log.Infoln("GetConfigFileServer server '" + serverNameOrID + "' fileName '" + fileName + "'")
	if getCfgFunc, ok := ServerConfigFileFuncs()[fileName]; ok {
		txt, err := getCfgFunc(cfg, serverNameOrID)
		if err != nil {
			return "", ExitCodeErrGeneric, err
		}
		return txt, ExitCodeSuccess, nil
	}
	return GetConfigFileFromTrafficOps(cfg)
}

func GetConfigFileFromTrafficOps(cfg TCCfg) (string, int, error) {
	path := cfg.TOURL.Path
	if cfg.TOURL.RawQuery != "" {
		path += "?" + cfg.TOURL.RawQuery
	}
	log.Infoln("GetConfigFile path '" + path + "' not generated locally, requesting from Traffic Ops")
	log.Infoln("GetConfigFile url '" + cfg.TOURL.String() + "'")

	body, code, err := TrafficOpsRequest(cfg, http.MethodGet, cfg.TOURL.String(), nil)
	if err != nil {
		return "", code, errors.New("Requesting path '" + path + "': " + err.Error())
	}

	WriteCookiesToFile(CookiesToString((*cfg.TOClient).Client.Jar.Cookies(cfg.TOURL)), cfg.TempDir)

	return string(body), HTTPCodeToExitCode(code), nil
}
