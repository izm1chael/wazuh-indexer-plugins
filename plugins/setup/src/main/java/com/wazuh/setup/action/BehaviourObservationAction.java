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

public final class BehaviourObservationAction extends ActionType<IncidentReadResponse> {
    public static final String PUBLISH_NAME="cluster:admin/wazuh/incident/behaviour_publish";
    public static final String READ_NAME="cluster:admin/wazuh/incident/behaviour_observation_read";
    public static final String REVIEW_NAME="cluster:admin/wazuh/incident/behaviour_review";
    public static final String PROMOTE_NAME="cluster:admin/wazuh/incident/behaviour_promote";
    public static final BehaviourObservationAction PUBLISH=new BehaviourObservationAction(PUBLISH_NAME);
    public static final BehaviourObservationAction READ=new BehaviourObservationAction(READ_NAME);
    public static final BehaviourObservationAction REVIEW=new BehaviourObservationAction(REVIEW_NAME);
    public static final BehaviourObservationAction PROMOTE=new BehaviourObservationAction(PROMOTE_NAME);
    private BehaviourObservationAction(String name){super(name,IncidentReadResponse::new);}
}
