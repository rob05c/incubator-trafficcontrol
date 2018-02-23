package tc

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

type PhysLocationsResponse struct {
	Response []PhysLocation `json:"response"`
}

type PhysLocation struct {
	Address     string `json:"address" db:"address"`
	City        string `json:"city" db:"city"`
	Comments    string `json:"comments" db:"comments"`
	Email       string `json:"email" db:"email"`
	ID          int    `json:"id" db:"id"`
	LastUpdated Time   `json:"lastUpdated" db:"last_updated"`
	Name        string `json:"name" db:"name"`
	Phone       string `json:"phone" db:"phone"`
	POC         string `json:"poc" db:"poc"`
	RegionID    int    `json:"regionId" db:"region_id"`
	RegionName  string `json:"regionName" db:"region_name"`
	ShortName   string `json:"shortName" db:"short_name"`
	State       string `json:"state" db:"state"`
	Zip         string `json:"zip" db:"zip"`
}

// PhysLocationNullable - a struct version that allows for all fields to be null
type PhysLocationNullable struct {
	//
	// NOTE: the db: struct tags are used for testing to map to their equivalent database column (if there is one)
	//
	Address     *string `json:"address" db:"address"`
	City        *string `json:"city" db:"city"`
	Comments    *string `json:"comments" db:"comments"`
	Email       *string `json:"email" db:"email"`
	ID          *int    `json:"id" db:"id"`
	LastUpdated Time    `json:"lastUpdated" db:"last_updated"`
	Name        *string `json:"name" db:"name"`
	Phone       *string `json:"phone" db:"phone"`
	POC         *string `json:"poc" db:"poc"`
	RegionID    *int    `json:"regionId" db:"region_id"`
	RegionName  *string `json:"regionName" db:"region_name"`
	ShortName   *string `json:"shortName" db:"short_name"`
	State       *string `json:"state" db:"state"`
	Zip         *string `json:"zip" db:"zip"`
}
