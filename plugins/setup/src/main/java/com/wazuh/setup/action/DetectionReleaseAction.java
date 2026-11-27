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

public final class DetectionReleaseAction extends ActionType<IncidentReadResponse> {
    public static final String SUBMIT_NAME="cluster:admin/wazuh/detection/release_submit";
    public static final String READ_NAME="cluster:admin/wazuh/detection/release_read";
    public static final String DAY_NAME="cluster:admin/wazuh/detection/release_day";
    public static final String REVIEW_NAME="cluster:admin/wazuh/detection/release_review";
    public static final DetectionReleaseAction SUBMIT=new DetectionReleaseAction(SUBMIT_NAME);
    public static final DetectionReleaseAction READ=new DetectionReleaseAction(READ_NAME);
    public static final DetectionReleaseAction DAY=new DetectionReleaseAction(DAY_NAME);
    public static final DetectionReleaseAction REVIEW=new DetectionReleaseAction(REVIEW_NAME);
    private DetectionReleaseAction(String name){super(name,IncidentReadResponse::new);}
}
