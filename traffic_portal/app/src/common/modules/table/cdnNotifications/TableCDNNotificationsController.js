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

var TableCDNNotificationsController = function(cdn, notifications, filter, $controller, $scope) {

	// extends the TableNotificationsController to inherit common methods
	angular.extend(this, $controller('TableNotificationsController', { tableName: 'cdnNotifications', notifications: notifications, filter: filter, $scope: $scope }));

	$scope.cdn = cdn;
};

TableCDNNotificationsController.$inject = ['cdn', 'notifications', 'filter', '$controller', '$scope'];
module.exports = TableCDNNotificationsController;
