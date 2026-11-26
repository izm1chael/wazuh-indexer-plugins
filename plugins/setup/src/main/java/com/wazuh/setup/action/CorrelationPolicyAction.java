/*
 * Copyright (C) 2024-2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.setup.action;

import org.opensearch.action.ActionType;

public final class CorrelationPolicyAction extends ActionType<IncidentReadResponse> {
    public static final String READ_NAME = "cluster:admin/wazuh/incident/correlation_policy_read";
    public static final String SAVE_NAME = "cluster:admin/wazuh/incident/correlation_policy_save";
    public static final CorrelationPolicyAction READ = new CorrelationPolicyAction(READ_NAME);
    public static final CorrelationPolicyAction SAVE = new CorrelationPolicyAction(SAVE_NAME);
    private CorrelationPolicyAction(String name) { super(name, IncidentReadResponse::new); }
}
