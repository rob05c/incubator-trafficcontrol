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
	"errors"
	"fmt"
	"net/http"

	"github.com/apache/trafficcontrol/lib/go-tc"
	"github.com/apache/trafficcontrol/lib/go-tc/tovalidate"
	"github.com/apache/trafficcontrol/lib/go-util"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/api"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/dbhelpers"
	"github.com/apache/trafficcontrol/traffic_ops/traffic_ops_golang/tenant"

	"github.com/go-ozzo/ozzo-validation"
	"github.com/jmoiron/sqlx"
)

const (
	deliveryServiceQueryParam    = "deliveryServiceID"
	requiredCapabilityQueryParam = "requiredCapability"
	xmlIDQueryParam              = "xmlID"
)

// RequiredCapability provides a type to define methods on.
type RequiredCapability struct {
	api.APIInfoImpl `json:"-"`
	tc.DeliveryServicesRequiredCapability
}

// SetLastUpdated implements the api.GenericCreator interfaces and
// sets the timestamp on insert.
func (rc *RequiredCapability) SetLastUpdated(t tc.TimeNoMod) { rc.LastUpdated = &t }

// NewReadObj implements the api.GenericReader interfaces.
func (rc *RequiredCapability) NewReadObj() interface{} {
	return &tc.DeliveryServicesRequiredCapability{}
}

// SelectQuery implements the api.GenericReader interface.
func (rc *RequiredCapability) SelectQuery() string {
	return `SELECT
	rc.required_capability,
	rc.deliveryservice_id,
	ds.xml_id,
	rc.last_updated
	FROM deliveryservices_required_capability rc
	JOIN deliveryservice ds ON ds.id = rc.deliveryservice_id`
}

// ParamColumns implements the api.GenericReader interface.
func (rc *RequiredCapability) ParamColumns() map[string]dbhelpers.WhereColumnInfo {
	return map[string]dbhelpers.WhereColumnInfo{
		deliveryServiceQueryParam: dbhelpers.WhereColumnInfo{
			Column:  "rc.deliveryservice_id",
			Checker: api.IsInt,
		},
		xmlIDQueryParam: dbhelpers.WhereColumnInfo{
			Column:  "ds.xml_id",
			Checker: nil,
		},
		requiredCapabilityQueryParam: dbhelpers.WhereColumnInfo{
			Column:  "rc.required_capability",
			Checker: nil,
		},
	}
}

// DeleteQuery implements the api.GenericDeleter interface.
func (rc *RequiredCapability) DeleteQuery() string {
	return `DELETE FROM deliveryservices_required_capability
	WHERE deliveryservice_id = :deliveryservice_id`
}

// GetKeyFieldsInfo implements the api.Identifier interface.
func (rc RequiredCapability) GetKeyFieldsInfo() []api.KeyFieldInfo {
	return []api.KeyFieldInfo{
		{
			Field: deliveryServiceQueryParam,
			Func:  api.GetIntKey,
		},
	}
}

// GetKeys implements the api.Identifier interface and is not needed
// because Update is not available.
func (rc RequiredCapability) GetKeys() (map[string]interface{}, bool) {
	if rc.DeliveryServiceID == nil {
		return map[string]interface{}{deliveryServiceQueryParam: 0}, false
	}
	return map[string]interface{}{
		deliveryServiceQueryParam: *rc.DeliveryServiceID,
	}, true
}

// SetKeys implements the api.Identifier interface and allows the
// create handler to assign deliveryServiceID and requiredCapability.
func (rc *RequiredCapability) SetKeys(keys map[string]interface{}) {
	// this utilizes the non panicking type assertion, if the thrown
	// away ok variable is false it will be the zero of the type.
	id, _ := keys[deliveryServiceQueryParam].(int)
	rc.DeliveryServiceID = &id
}

// GetAuditName implements the api.Identifier interface and
// returns the name of the object.
func (rc *RequiredCapability) GetAuditName() string {
	if rc.RequiredCapability != nil {
		return *rc.RequiredCapability
	}

	return "unknown"
}

// GetType implements the api.Identifier interface and
// returns the name of the struct.
func (rc *RequiredCapability) GetType() string {
	return "deliveryservice.RequiredCapability"
}

// Validate implements the api.Validator interface.
func (rc RequiredCapability) Validate() error {
	errs := validation.Errors{
		deliveryServiceQueryParam:    validation.Validate(rc.DeliveryServiceID, validation.Required),
		requiredCapabilityQueryParam: validation.Validate(rc.RequiredCapability, validation.Required),
	}

	return util.JoinErrs(tovalidate.ToErrors(errs))
}

// Update implements the api.CRUDer interface.
func (rc *RequiredCapability) Update() (error, error, int) {
	return nil, nil, http.StatusNotImplemented
}

// Read implements the api.CRUDer interface.
func (rc *RequiredCapability) Read() ([]interface{}, error, error, int) {
	tenantIDs, err := rc.getTenantIDs()
	if err != nil {
		return nil, nil, err, http.StatusInternalServerError
	}

	capabilities, userErr, sysErr, errCode := rc.getCapabilities(tenantIDs)
	if userErr != nil || sysErr != nil {
		return nil, userErr, sysErr, errCode
	}

	results := []interface{}{}
	for _, capability := range capabilities {
		results = append(results, capability)
	}

	return results, nil, nil, http.StatusOK
}

func (rc *RequiredCapability) getTenantIDs() ([]int, error) {
	tenantIDs, err := tenant.GetUserTenantIDListTx(rc.APIInfo().Tx.Tx, rc.APIInfo().User.TenantID)
	if err != nil {
		return nil, err
	}
	return tenantIDs, nil
}

func (rc *RequiredCapability) getCapabilities(tenantIDs []int) ([]tc.DeliveryServicesRequiredCapability, error, error, int) {
	where, orderBy, pagination, queryValues, errs := dbhelpers.BuildWhereAndOrderByAndPagination(rc.APIInfo().Params, rc.ParamColumns())
	if len(errs) > 0 {
		return nil, util.JoinErrs(errs), nil, http.StatusBadRequest
	}

	where, queryValues = dbhelpers.AddTenancyCheck(where, queryValues, "ds.tenant_id", tenantIDs)
	query := rc.SelectQuery() + where + orderBy + pagination

	rows, err := rc.APIInfo().Tx.NamedQuery(query, queryValues)
	if err != nil {
		return nil, nil, err, http.StatusInternalServerError
	}
	defer rows.Close()

	var results []tc.DeliveryServicesRequiredCapability
	for rows.Next() {
		var result tc.DeliveryServicesRequiredCapability
		if err := rows.StructScan(&result); err != nil {
			return nil, nil, errors.New(rc.GetType() + " get scanning: " + err.Error()), http.StatusInternalServerError
		}
		results = append(results, result)
	}

	return results, nil, nil, 0
}

// Delete implements the api.CRUDer interface.
func (rc *RequiredCapability) Delete() (error, error, int) {
	authorized, err := rc.isTenantAuthorized()
	if err != nil {
		return nil, errors.New("checking tenant: " + err.Error()), http.StatusInternalServerError
	} else if !authorized {
		return errors.New("not authorized on this tenant"), nil, http.StatusForbidden
	}

	return api.GenericDelete(rc)
}

// Create implements the api.CRUDer interface.
func (rc *RequiredCapability) Create() (error, error, int) {
	authorized, err := rc.isTenantAuthorized()
	if err != nil {
		return nil, errors.New("checking tenant: " + err.Error()), http.StatusInternalServerError
	} else if !authorized {
		return errors.New("not authorized on this tenant"), nil, http.StatusForbidden
	}

	if userErr, sysErr, errCode := validateRequiredCapabilities(rc.APIInfo().Tx, *rc.RequiredCapability); userErr != nil || sysErr != nil {
		return userErr, sysErr, errCode
	}

	rows, err := rc.APIInfo().Tx.NamedQuery(rcInsertQuery(), rc)
	if err != nil {
		return api.ParseDBError(err)
	}
	defer rows.Close()

	rowsAffected := 0
	for rows.Next() {
		rowsAffected++
		if err := rows.StructScan(&rc); err != nil {
			return nil, errors.New(rc.GetType() + " create scanning: " + err.Error()), http.StatusInternalServerError
		}
	}
	if rowsAffected == 0 {
		return nil, errors.New(rc.GetType() + " create: no " + rc.GetType() + " was inserted, no rows was returned"), http.StatusInternalServerError
	} else if rowsAffected > 1 {
		return nil, errors.New("too many rows returned from " + rc.GetType() + " insert"), http.StatusInternalServerError
	}

	return nil, nil, http.StatusOK
}

func (rc *RequiredCapability) isTenantAuthorized() (bool, error) {
	if rc.DeliveryServiceID == nil && rc.XMLID == nil {
		return false, errors.New("delivery service has no ID or XMLID")
	}

	var existingID *int
	var err error

	switch {
	case rc.DeliveryServiceID != nil:
		existingID, _, err = getDSTenantIDByID(rc.APIInfo().Tx.Tx, *rc.DeliveryServiceID)
		if err != nil {
			return false, err
		}
	case rc.XMLID != nil:
		existingID, _, err = getDSTenantIDByName(rc.APIInfo().Tx.Tx, tc.DeliveryServiceName(*rc.XMLID))
		if err != nil {
			return false, err
		}
	}

	if existingID != nil {
		authorized, err := tenant.IsResourceAuthorizedToUserTx(*existingID, rc.APIInfo().User, rc.APIInfo().Tx.Tx)
		if err != nil {
			return false, fmt.Errorf("checking authorization for existing DS ID: %s" + err.Error())
		}
		if !authorized {
			return false, errors.New("not authorized on this tenant")
		}
	}

	return true, err
}

func rcInsertQuery() string {
	return `INSERT INTO deliveryservices_required_capability (
required_capability,
deliveryservice_id) VALUES (
:required_capability,
:deliveryservice_id) RETURNING deliveryservice_id, required_capability, last_updated`
}

// validateCapabilities validates the given required capabilities expression.
// Returns the user error, the system error, and the HTTP error code.
func validateRequiredCapabilities(tx *sqlx.Tx, requiredCapsExpr string) (error, error, int) {
	expr, err := util.ParseBoolExpr(requiredCapsExpr)
	if err != nil {
		return errors.New("Required capability '" + requiredCapsExpr + "' is not a valid expression: " + err.Error()), nil, http.StatusBadRequest
	}

	exprCaps := expr.Symbols()

	dbCaps, err := getServerCapabilities(tx)
	if err != nil {
		return nil, errors.New("received error querying for user's tenants: " + err.Error()), http.StatusInternalServerError
	}

	for exprCap, _ := range exprCaps {
		if _, ok := dbCaps[exprCap]; !ok {
			return errors.New("Required capability '" + requiredCapsExpr + "' capability '" + exprCap + "' not found"), nil, http.StatusBadRequest
		}
	}
	return nil, nil, http.StatusOK
}

func getServerCapabilities(tx *sqlx.Tx) (map[string]struct{}, error) {
	rows, err := tx.Query(`SELECT name FROM server_capability`)
	if err != nil {
		return nil, errors.New("querying: " + err.Error())
	}
	defer rows.Close()

	caps := map[string]struct{}{}
	for rows.Next() {
		cap := ""
		if err := rows.Scan(&cap); err != nil {
			return nil, errors.New("scanning: " + err.Error())
		}
		caps[cap] = struct{}{}
	}
	return caps, nil
}
