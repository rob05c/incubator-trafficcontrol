package federation_resolvers

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

import "fmt"
import "net/http"

import "github.com/apache/trafficcontrol/lib/go-tc"
import "github.com/apache/trafficcontrol/lib/go-util"

import "github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/api"
import "github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/dbhelpers"

const insertFederationResolverQuery = `
INSERT INTO federation_resolver (ip_address, type)
VALUES ($1, $2)
RETURNING federation_resolver.id,
          federation_resolver.ip_address,
          (
          	SELECT type.name
          	FROM type
          	WHERE type.id = federation_resolver.type
          ) AS type
`

const readQuery = `
SELECT federation_resolver.id,
       federation_resolver.ip_address,
       federation_resolver.last_updated,
       type.name AS type
FROM federation_resolver
LEFT OUTER JOIN type ON type.id = federation_resolver.type
`

func Create(w http.ResponseWriter, r *http.Request) {
	inf, sysErr, userErr, errCode := api.NewInfo(r, nil, nil)
	tx := inf.Tx.Tx
	if sysErr != nil || userErr != nil {
		api.HandleErr(w, r, tx, errCode, userErr, sysErr)
		return
	}
	defer inf.Close()

	var fr tc.FederationResolver
	if userErr = api.Parse(r.Body, tx, &fr); userErr != nil {
		api.HandleErr(w, r, tx, http.StatusBadRequest, userErr, nil)
		return
	}

	err := tx.QueryRow(insertFederationResolverQuery, fr.IPAddress, fr.TypeID).Scan(&fr.ID, &fr.IPAddress, &fr.Type)
	if err != nil {
		userErr, sysErr, errCode = api.ParseDBError(err)
		api.HandleErr(w, r, tx, errCode, userErr, sysErr)
		return
	}

	fr.TypeID = nil
	if inf.Version.Major < 2 && inf.Version.Minor < 4 {
		fr.LastUpdated = nil
	}

	changeLogMsg := fmt.Sprintf("FEDERATION_RESOLVER: %s, ID: %d, ACTION: Created", *fr.IPAddress, *fr.ID)
	api.CreateChangeLogRawTx(api.ApiChange, changeLogMsg, inf.User, tx, r)

	alertMsg := fmt.Sprintf("Federation Resolver created [ IP = %s ] with id: %d", *fr.IPAddress, *fr.ID)
	api.WriteRespAlertObj(w, r, tc.SuccessLevel, alertMsg, fr)
}

func Read(w http.ResponseWriter, r *http.Request) {
	inf, sysErr, userErr, errCode := api.NewInfo(r, nil, nil)
	tx := inf.Tx.Tx
	if sysErr != nil || userErr != nil {
		api.HandleErr(w, r, tx, errCode, userErr, sysErr)
		return
	}
	defer inf.Close()

	queryParamsToQueryCols := map[string]dbhelpers.WhereColumnInfo{
		"id":        dbhelpers.WhereColumnInfo{"federation_resolver.id", api.IsInt},
		"ipAddress": dbhelpers.WhereColumnInfo{"federation_resolver.ip_address", nil},
		"type":      dbhelpers.WhereColumnInfo{"type.name", nil},
	}

	where, orderBy, pagination, queryValues, errs := dbhelpers.BuildWhereAndOrderByAndPagination(inf.Params, queryParamsToQueryCols)
	if len(errs) > 0 {
		sysErr = util.JoinErrs(errs)
		errCode = http.StatusBadRequest
		api.HandleErr(w, r, tx, errCode, nil, sysErr)
		return
	}

	query := readQuery + where + orderBy + pagination
	rows, err := inf.Tx.NamedQuery(query, queryValues)
	if err != nil {
		userErr, sysErr, errCode = api.ParseDBError(err)
		if sysErr != nil {
			sysErr = fmt.Errorf("federation_resolver read query: %v", sysErr)
		}

		api.HandleErr(w, r, tx, errCode, userErr, sysErr)
		return
	}
	defer rows.Close()

	var resolvers = []tc.FederationResolver{}
	for rows.Next() {
		var resolver tc.FederationResolver
		if err := rows.Scan(&resolver.ID, &resolver.IPAddress, &resolver.LastUpdated, &resolver.Type); err != nil {
			userErr, sysErr, errCode = api.ParseDBError(err)
			if sysErr != nil {
				sysErr = fmt.Errorf("federation_resolver scanning: %v", sysErr)
			}
			api.HandleErr(w, r, tx, errCode, userErr, sysErr)
			return
		}

		resolvers = append(resolvers, resolver)
	}

	api.WriteResp(w, r, resolvers)
}
