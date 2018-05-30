package manager

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
	"fmt"
	"os"
	"strings"
	"time"
	"errors"

	"github.com/apache/incubator-trafficcontrol/lib/go-log"
	"github.com/apache/incubator-trafficcontrol/lib/go-tc"
	"github.com/apache/incubator-trafficcontrol/traffic_monitor/config"
	"github.com/apache/incubator-trafficcontrol/traffic_monitor/cache"
	"github.com/apache/incubator-trafficcontrol/traffic_monitor/peer"
	"github.com/apache/incubator-trafficcontrol/traffic_monitor/poller"
	"github.com/apache/incubator-trafficcontrol/traffic_monitor/threadsafe"
	"github.com/apache/incubator-trafficcontrol/traffic_monitor/todata"
	"github.com/apache/incubator-trafficcontrol/traffic_monitor/towrap"
)

type PollIntervals struct {
	Health            time.Duration
	HealthNoKeepAlive bool
	Peer              time.Duration
	PeerNoKeepAlive   bool
	Stat              time.Duration
	StatNoKeepAlive   bool
	TO                time.Duration
}

// getPollIntervals reads the Traffic Ops Client monitorConfig structure, and parses and returns the health, peer, stat, and TrafficOps poll intervals
func getIntervals(monitorConfig tc.TrafficMonitorConfigMap, cfg config.Config, logMissingParams bool) (PollIntervals, error) {
	intervals := PollIntervals{}
	peerPollIntervalI, peerPollIntervalExists := monitorConfig.Config["peers.polling.interval"]
	if !peerPollIntervalExists {
		return PollIntervals{}, fmt.Errorf("Traffic Ops Monitor config missing 'peers.polling.interval', not setting config changes.\n")
	}
	peerPollIntervalInt, peerPollIntervalIsInt := peerPollIntervalI.(float64)
	if !peerPollIntervalIsInt {
		return PollIntervals{}, fmt.Errorf("Traffic Ops Monitor config 'peers.polling.interval' value '%v' type %T is not an integer, not setting config changes.\n", peerPollIntervalI, peerPollIntervalI)
	}
	intervals.Peer = trafficOpsPeerPollIntervalToDuration(int(peerPollIntervalInt))

	statPollIntervalI, statPollIntervalExists := monitorConfig.Config["health.polling.interval"]
	if !statPollIntervalExists {
		return PollIntervals{}, fmt.Errorf("Traffic Ops Monitor config missing 'health.polling.interval', not setting config changes.\n")
	}
	statPollIntervalInt, statPollIntervalIsInt := statPollIntervalI.(float64)
	if !statPollIntervalIsInt {
		return PollIntervals{}, fmt.Errorf("Traffic Ops Monitor config 'health.polling.interval' value '%v' type %T is not an integer, not setting config changes.\n", statPollIntervalI, statPollIntervalI)
	}
	intervals.Stat = trafficOpsStatPollIntervalToDuration(int(statPollIntervalInt))

	healthPollIntervalI, healthPollIntervalExists := monitorConfig.Config["heartbeat.polling.interval"]
	healthPollIntervalInt, healthPollIntervalIsInt := healthPollIntervalI.(float64)
	if !healthPollIntervalExists {
		if logMissingParams {
			log.Warnln("Traffic Ops Monitor config missing 'heartbeat.polling.interval', using health for heartbeat.")
		}
		healthPollIntervalInt = statPollIntervalInt
	} else if !healthPollIntervalIsInt {
		log.Warnf("Traffic Ops Monitor config 'heartbeat.polling.interval' value '%v' type %T is not an integer, using health for heartbeat\n", statPollIntervalI, statPollIntervalI)
		healthPollIntervalInt = statPollIntervalInt
	}
	intervals.Health = trafficOpsHealthPollIntervalToDuration(int(healthPollIntervalInt))

	toPollIntervalI, toPollIntervalExists := monitorConfig.Config["tm.polling.interval"]
	toPollIntervalInt, toPollIntervalIsInt := toPollIntervalI.(float64)
	intervals.TO = cfg.MonitorConfigPollingInterval
	if !toPollIntervalExists {
		if logMissingParams {
			log.Warnf("Traffic Ops Monitor config missing 'tm.polling.interval', using config value '%v'\n", cfg.MonitorConfigPollingInterval)
		}
	} else if !toPollIntervalIsInt {
		log.Warnf("Traffic Ops Monitor config 'tm.polling.interval' value '%v' type %T is not an integer, using config value '%v'\n", toPollIntervalI, toPollIntervalI, cfg.MonitorConfigPollingInterval)
	} else {
		intervals.TO = trafficOpsTOPollIntervalToDuration(int(toPollIntervalInt))
	}

	getNoKeepAlive := func(param string) bool {
		keepAliveI, keepAliveExists := monitorConfig.Config[param]
		keepAliveStr, keepAliveIsStr := keepAliveI.(string)
		return keepAliveExists && keepAliveIsStr && !strings.HasPrefix(strings.ToLower(keepAliveStr), "t")
	}
	intervals.PeerNoKeepAlive = getNoKeepAlive("peer.polling.keepalive")
	intervals.HealthNoKeepAlive = getNoKeepAlive("health.polling.keepalive")
	intervals.StatNoKeepAlive = getNoKeepAlive("stat.polling.keepalive")

	multiplyByRatio := func(i time.Duration) time.Duration {
		return time.Duration(float64(i) * PollIntervalRatio)
	}

	intervals.TO = multiplyByRatio(intervals.TO)
	intervals.Health = multiplyByRatio(intervals.Health)
	intervals.Peer = multiplyByRatio(intervals.Peer)
	intervals.Stat = multiplyByRatio(intervals.Stat)
	return intervals, nil
}

// StartMonitorConfigManager runs the monitor config manager goroutine, and returns the threadsafe data which it sets.
func StartMonitorConfigManager(
	monitorConfigPollChan <-chan poller.MonitorCfg,
	localStates peer.CRStatesThreadsafe,
	peerStates peer.CRStatesPeersThreadsafe,
	statURLSubscriber chan<- poller.HttpPollerConfig,
	healthURLSubscriber chan<- poller.HttpPollerConfig,
	peerURLSubscriber chan<- poller.HttpPollerConfig,
	toIntervalSubscriber chan<- time.Duration,
	cachesChangeSubscriber chan<- struct{},
	cfg config.Config,
	staticAppData config.StaticAppData,
	toSession towrap.ITrafficOpsSession,
	toData todata.TODataThreadsafe,
) threadsafe.TrafficMonitorConfigMap {
	monitorConfig := threadsafe.NewTrafficMonitorConfigMap()
	go monitorConfigListen(monitorConfig,
		monitorConfigPollChan,
		localStates,
		peerStates,
		statURLSubscriber,
		healthURLSubscriber,
		peerURLSubscriber,
		toIntervalSubscriber,
		cachesChangeSubscriber,
		cfg,
		staticAppData,
		toSession,
		toData,
	)
	return monitorConfig
}

const DefaultHealthConnectionTimeout = time.Second * 2

// trafficOpsHealthConnectionTimeoutToDuration takes the int from Traffic Ops, which is in milliseconds, and returns a time.Duration
// TODO change Traffic Ops Client API to a time.Duration
func trafficOpsHealthConnectionTimeoutToDuration(t int) time.Duration {
	return time.Duration(t) * time.Millisecond
}

// trafficOpsPeerPollIntervalToDuration takes the int from Traffic Ops, which is in milliseconds, and returns a time.Duration
// TODO change Traffic Ops Client API to a time.Duration
func trafficOpsPeerPollIntervalToDuration(t int) time.Duration {
	return time.Duration(t) * time.Millisecond
}

// trafficOpsStatPollIntervalToDuration takes the int from Traffic Ops, which is in milliseconds, and returns a time.Duration
// TODO change Traffic Ops Client API to a time.Duration
func trafficOpsStatPollIntervalToDuration(t int) time.Duration {
	return time.Duration(t) * time.Millisecond
}

// trafficOpsHealthPollIntervalToDuration takes the int from Traffic Ops, which is in milliseconds, and returns a time.Duration
// TODO change Traffic Ops Client API to a time.Duration
func trafficOpsHealthPollIntervalToDuration(t int) time.Duration {
	return time.Duration(t) * time.Millisecond
}

// trafficOpsTOPollIntervalToDuration takes the int from Traffic Ops, which is in milliseconds, and returns a time.Duration
// TODO change Traffic Ops Client API to a time.Duration
func trafficOpsTOPollIntervalToDuration(t int) time.Duration {
	return time.Duration(t) * time.Millisecond
}

// PollIntervalRatio is the ratio of the configuration interval to poll. The configured intervals are 'target' times, so we actually poll at some small fraction less, in attempt to make the actual poll marginally less than the target.
const PollIntervalRatio = float64(0.97) // TODO make config?

// TODO timing, and determine if the case, or its internal `for`, should be put in a goroutine
// TODO determine if subscribers take action on change, and change to mutexed objects if not.
func monitorConfigListen(
	monitorConfigTS threadsafe.TrafficMonitorConfigMap,
	monitorConfigPollChan <-chan poller.MonitorCfg,
	localStates peer.CRStatesThreadsafe,
	peerStates peer.CRStatesPeersThreadsafe,
	statURLSubscriber chan<- poller.HttpPollerConfig,
	healthURLSubscriber chan<- poller.HttpPollerConfig,
	peerURLSubscriber chan<- poller.HttpPollerConfig,
	toIntervalSubscriber chan<- time.Duration,
	cachesChangeSubscriber chan<- struct{},
	cfg config.Config,
	staticAppData config.StaticAppData,
	toSession towrap.ITrafficOpsSession,
	toData todata.TODataThreadsafe,
) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("MonitorConfigManager panic: %v\n", err)
		} else {
			log.Errorf("MonitorConfigManager failed without panic\n")
		}
		os.Exit(1) // The Monitor can't run without a MonitorConfigManager
	}()

	logMissingIntervalParams := true

	for pollerMonitorCfg := range monitorConfigPollChan {
		monitorConfig := pollerMonitorCfg.Cfg
		cdn := pollerMonitorCfg.CDN
		monitorConfigTS.Set(monitorConfig)
		if err := toData.Update(toSession, cdn); err != nil {
			log.Errorln("Updating Traffic Ops Data: " + err.Error())
		}

		healthURLs := map[string]poller.PollConfig{}
		statURLs := map[string]poller.PollConfig{}
		peerURLs := map[string]poller.PollConfig{}
		caches := map[string]string{}

		cgPoll := getPollingCachegroups(monitorConfig.Config, logMissingIntervalParams)
		intervals, err := getIntervals(monitorConfig, cfg, logMissingIntervalParams)
		logMissingIntervalParams = false // only log missing parameters once
		if err != nil {
			log.Errorf("monitor config error getting polling intervals, can't poll: %v", err)
			continue
		}

		for _, srv := range monitorConfig.TrafficServer {
			caches[srv.HostName] = srv.ServerStatus

			cacheName := tc.CacheName(srv.HostName)

			srvStatus := tc.CacheStatusFromString(srv.ServerStatus)
			if srvStatus == tc.CacheStatusOnline {
				localStates.AddCache(cacheName, tc.IsAvailable{IsAvailable: true})
				continue
			}
			if srvStatus == tc.CacheStatusOffline {
				continue
			}
			// seed states with available = false until our polling cycle picks up a result
			if _, exists := localStates.GetCache(cacheName); !exists {
				localStates.AddCache(cacheName, tc.IsAvailable{IsAvailable: false})
			}

			url := monitorConfig.Profile[srv.Profile].Parameters.HealthPollingURL
			if url == "" {
				log.Errorf("monitor config server %v profile %v has no polling URL; can't poll", srv.HostName, srv.Profile)
				continue
			}

			format := monitorConfig.Profile[srv.Profile].Parameters.HealthPollingFormat
			if format == "" {
				format = cache.DefaultStatsType
				log.Infof("health.polling.format for '%v' is empty, using default '%v'", srv.HostName, format)
			}

			r := strings.NewReplacer(
				"${hostname}", srv.IP,
				"${interface_name}", srv.InterfaceName,
				"application=plugin.remap", "application=system",
				"application=", "application=system",
			)
			url = r.Replace(url)

			connTimeout := trafficOpsHealthConnectionTimeoutToDuration(monitorConfig.Profile[srv.Profile].Parameters.HealthConnectionTimeout)
			if connTimeout == 0 {
				connTimeout = DefaultHealthConnectionTimeout
				log.Warnln("profile " + srv.Profile + " health.connection.timeout Parameter is missing or zero, using default " + DefaultHealthConnectionTimeout.String())
			}

			if len(cgPoll[tc.CacheGroupName(srv.CacheGroup)]) > 0 {
				if _, ok := cgPoll[tc.CacheGroupName(srv.CacheGroup)][tc.TrafficMonitorName(staticAppData.Hostname)]; !ok {
					continue
				}
			}

			healthURLs[srv.HostName] = poller.PollConfig{URL: url, Host: srv.FQDN, Timeout: connTimeout, Format: format}
			statURL := strings.NewReplacer("application=system", "application=").Replace(url)
			statURLs[srv.HostName] = poller.PollConfig{URL: statURL, Host: srv.FQDN, Timeout: connTimeout, Format: format}
		}

		peerSet := map[tc.TrafficMonitorName]struct{}{}
		for _, srv := range monitorConfig.TrafficMonitor {
			if srv.HostName == staticAppData.Hostname {
				continue
			}
			if tc.CacheStatusFromString(srv.ServerStatus) != tc.CacheStatusOnline {
				continue
			}
			// TODO: the URL should be config driven. -jse
			url := fmt.Sprintf("http://%s:%d/publish/CrStates?raw", srv.IP, srv.Port)
			peerURLs[srv.HostName] = poller.PollConfig{URL: url, Host: srv.FQDN} // TODO determine timeout.
			peerSet[tc.TrafficMonitorName(srv.HostName)] = struct{}{}
		}

		statURLSubscriber <- poller.HttpPollerConfig{Urls: statURLs, Interval: intervals.Stat, NoKeepAlive: intervals.StatNoKeepAlive}
		healthURLSubscriber <- poller.HttpPollerConfig{Urls: healthURLs, Interval: intervals.Health, NoKeepAlive: intervals.HealthNoKeepAlive}
		peerURLSubscriber <- poller.HttpPollerConfig{Urls: peerURLs, Interval: intervals.Peer, NoKeepAlive: intervals.PeerNoKeepAlive}
		toIntervalSubscriber <- intervals.TO
		peerStates.SetTimeout((intervals.Peer + cfg.HTTPTimeout) * 2)
		peerStates.SetPeers(peerSet)

		for cacheName := range localStates.GetCaches() {
			if _, exists := monitorConfig.TrafficServer[string(cacheName)]; !exists {
				log.Warnf("Removing %s from localStates", cacheName)
				localStates.DeleteCache(cacheName)
			}
		}

		if len(healthURLs) == 0 {
			log.Errorf("No REPORTED caches exist in Traffic Ops, nothing to poll.")
		}

		cachesChangeSubscriber <- struct{}{}

		// TODO because there are multiple writers to localStates.DeliveryService, there is a race condition, where MonitorConfig (this func) and HealthResultManager could write at the same time, and the HealthResultManager could overwrite a delivery service addition or deletion here. Probably the simplest and most performant fix would be a lock-free algorithm using atomic compare-and-swaps.
		for _, ds := range monitorConfig.DeliveryService {
			// since caches default to unavailable, also default DS false
			if _, exists := localStates.GetDeliveryService(tc.DeliveryServiceName(ds.XMLID)); !exists {
				localStates.SetDeliveryService(tc.DeliveryServiceName(ds.XMLID), tc.CRStatesDeliveryService{IsAvailable: false, DisabledLocations: []tc.CacheGroupName{}}) // important to initialize DisabledLocations, so JSON is `[]` not `null`
			}
		}
		for ds := range localStates.GetDeliveryServices() {
			if _, exists := monitorConfig.DeliveryService[string(ds)]; !exists {
				localStates.DeleteDeliveryService(ds)
			}
		}
	}
}

const CachegroupPollingParameter = "health.polling.cachegroups"

// getPollingCachegroups gets the monitoring.json config health.polling.cachegroups, parses it into a map, and returns the map, or an empty map if unsuccessful. If unsuccessful, the reason is logged.
// Note this can be unsuccessful if the parameter does not exist. The caller should also poll all cachegroups which do not appear in the map. That will handle both the scenario of the parameter not existing, and of a particular cachegroup being omitted.
func getPollingCachegroups(cfg map[string]interface{}, logErrs bool) map[tc.CacheGroupName]map[tc.TrafficMonitorName]struct{} {
	cgPollI, cgPollExists := cfg[CachegroupPollingParameter]
	if !cgPollExists {
		if logErrs {
			log.Warnln("No health.polling.cachegroups parameter, polling all cachegroups")
		}
		return map[tc.CacheGroupName]map[tc.TrafficMonitorName]struct{}{}
	}

	cgPollStr, cgPollIsStr := cgPollI.(string)
	if !cgPollIsStr {
		if logErrs {
			log.Warnf("Parameter health.polling.cachegroups %T not a string, polling all cachegroups\n", cgPollI)
		}
		return map[tc.CacheGroupName]map[tc.TrafficMonitorName]struct{}{}
	}

	pollCGs, err := parsePollingCachegroups(cgPollStr)
	if err != nil {
		if logErrs {
			log.Errorln("Error parsing health.polling.cachegroups, polling all cachegroups: " + err.Error())
		}
		return map[tc.CacheGroupName]map[tc.TrafficMonitorName]struct{}{}
	}

	return pollCGs
}

// parsePollingCachegroups parses the health.polling.cachegroups parameter string, and returns a map of cachegroups to the monitors which poll them.
// The parameter string is of the format `monitor-hostname:cachegroup1,cachegroup2;monitor2:cachegroup3,cachegroup4
func parsePollingCachegroups(pollingCachegroups string) (map[tc.CacheGroupName]map[tc.TrafficMonitorName]struct{}, error) {
	cgMonitorMap := map[tc.CacheGroupName]map[tc.TrafficMonitorName]struct{}{}
	monitorGroups := strings.Split(pollingCachegroups, ";")
	for _, monitorGroup := range monitorGroups {
		monitorCachegroups := strings.SplitN(monitorGroup, ":", 2)
		if len(monitorCachegroups) != 2 {
			return nil, errors.New("malformed polling cachegroups string: '" + pollingCachegroups + "' at '" + monitorGroup + "'")
		}
		monitor := tc.TrafficMonitorName(monitorCachegroups[0])
		cachegroupsStr := monitorCachegroups[1]
		cachegroups := strings.Split(cachegroupsStr, ",")
		for _, cachegroupS := range cachegroups {
			cachegroup := tc.CacheGroupName(cachegroupS)
			if _, ok := cgMonitorMap[cachegroup]; !ok {
				cgMonitorMap[cachegroup] = map[tc.TrafficMonitorName]struct{}{}
			}
			cgMonitorMap[cachegroup][monitor] = struct{}{}
		}
	}
	return cgMonitorMap, nil
}
