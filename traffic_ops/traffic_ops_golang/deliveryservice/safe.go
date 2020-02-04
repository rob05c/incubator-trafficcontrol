package deliveryservice

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
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/api"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/tenant"
)

// UpdateSafe is the handler for updating the delivery service based on the payload that is set for DeliveryServiceSafeUpdate.
func UpdateSafe(w http.ResponseWriter, r *http.Request) {
	inf, userErr, sysErr, errCode := api.NewInfo(r, []string{"id"}, []string{"id"})
	if userErr != nil || sysErr != nil {
		api.HandleErr(w, r, inf.Tx.Tx, errCode, userErr, sysErr)
		return
	}
	defer inf.Close()

	dsID := inf.IntParams["id"]

	userErr, sysErr, errCode = tenant.CheckID(inf.Tx.Tx, inf.User, dsID)
	if userErr != nil || sysErr != nil {
		api.HandleErr(w, r, inf.Tx.Tx, errCode, userErr, sysErr)
		return
	}

	ds := tc.DeliveryServiceSafeUpdate{}
	if err := api.Parse(r.Body, inf.Tx.Tx, &ds); err != nil {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusBadRequest, errors.New("decoding: "+err.Error()), nil)
		return
	}

	ok, err := updateDSSafe(inf.Tx.Tx, dsID, ds)
	if err != nil {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusInternalServerError, nil, errors.New("updating delivery service safe: "+err.Error()))
		return
	}
	if !ok {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusNotFound, nil, nil)
		return
	}

	dses, userErr, sysErr, errCode := readGetDeliveryServices(inf.Params, inf.Tx, inf.User)
	if userErr != nil || sysErr != nil {
		api.HandleErr(w, r, inf.Tx.Tx, errCode, userErr, sysErr)
		return
	}
	if len(dses) != 1 {
		api.HandleErr(w, r, inf.Tx.Tx, http.StatusInternalServerError, nil, fmt.Errorf("delivery service safe update, read expected 1 delivery service, got %v", len(dses)))
		return
	}
	api.WriteRespAlertObj(w, r, tc.SuccessLevel, "Deliveryservice safe update was successful.", []tc.DeliveryServiceNullable{dses[0]})
}

// updateDSSafe updates the given delivery service in the database. Returns whether the DS existed, and any error.
func updateDSSafe(tx *sql.Tx, dsID int, ds tc.DeliveryServiceSafeUpdate) (bool, error) {
	q := `
UPDATE deliveryservice SET
display_name=$1,
info_url=$2,
long_desc=$3,
long_desc_1=$4
WHERE id = $5
RETURNING id
`
	res, err := tx.Exec(q, ds.DisplayName, ds.InfoURL, ds.LongDesc, ds.LongDesc1, dsID)
	if err != nil {
		return false, errors.New("updating delivery service safe: " + err.Error())
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return false, errors.New("updating delivery service safe, checking rows affected: " + err.Error())
	}
	if rowsAffected < 1 {
		return false, nil
	}
	if rowsAffected > 1 {
		return false, fmt.Errorf("updating delivery service safe, too many rows affected: %v", rowsAffected)
	}
	return true, nil
}
