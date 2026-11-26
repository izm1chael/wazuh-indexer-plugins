/*
 * Copyright (C) 2026, Wazuh Inc.
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

import com.wazuh.setup.incident.IncidentMutation.Operation;

/** Separate action identities prevent a grant for one workflow from authorising another. */
public final class IncidentWriteAction extends ActionType<IncidentWriteResponse> {
    public enum Grant {
        CREATE("create"), ASSIGN("assign"), UPDATE("update"), CLOSE("close"), REOPEN("reopen");

        private final String suffix;
        Grant(String suffix) { this.suffix = suffix; }

        public String actionName() { return "cluster:admin/wazuh/incident/" + suffix; }

        public boolean permits(Operation operation) {
            return switch (this) {
                case CREATE -> operation == Operation.CREATE;
                case ASSIGN -> operation == Operation.ASSIGN_SELF || operation == Operation.UNASSIGN;
                case UPDATE -> operation == Operation.START_TRIAGE || operation == Operation.ACTIVATE || operation == Operation.EDIT;
                case CLOSE -> operation == Operation.CLOSE;
                case REOPEN -> operation == Operation.REOPEN;
            };
        }
    }

    public static final IncidentWriteAction CREATE = new IncidentWriteAction(Grant.CREATE);
    public static final IncidentWriteAction ASSIGN = new IncidentWriteAction(Grant.ASSIGN);
    public static final IncidentWriteAction UPDATE = new IncidentWriteAction(Grant.UPDATE);
    public static final IncidentWriteAction CLOSE = new IncidentWriteAction(Grant.CLOSE);
    public static final IncidentWriteAction REOPEN = new IncidentWriteAction(Grant.REOPEN);

    private IncidentWriteAction(Grant grant) {
        super(grant.actionName(), IncidentWriteResponse::new);
    }
}
