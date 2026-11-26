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
package com.wazuh.setup.incident;

import org.opensearch.test.OpenSearchTestCase;

import com.wazuh.setup.action.IncidentWriteAction;
import com.wazuh.setup.rest.RestIncidentWriteAction;

public class IncidentRestDispatchTests extends OpenSearchTestCase {
    public void testRoutesBindDedicatedActions() {
        assertSame(IncidentWriteAction.CREATE, RestIncidentWriteAction.dispatch(null).action());
        assertSame(IncidentWriteAction.ASSIGN, RestIncidentWriteAction.dispatch("assign-self").action());
        assertSame(IncidentWriteAction.UPDATE, RestIncidentWriteAction.dispatch("activate").action());
        assertSame(IncidentWriteAction.CLOSE, RestIncidentWriteAction.dispatch("close").action());
        assertSame(IncidentWriteAction.REOPEN, RestIncidentWriteAction.dispatch("reopen").action());
        assertSame(IncidentWriteAction.FINDINGS, RestIncidentWriteAction.dispatch("attach-finding").action());
        assertSame(IncidentWriteAction.RESPONSE_REQUEST, RestIncidentWriteAction.dispatch("request-response").action());
        assertSame(IncidentWriteAction.RESPONSE_REQUEST, RestIncidentWriteAction.dispatch("cancel-response").action());
        assertSame(IncidentWriteAction.RESPONSE_APPROVAL, RestIncidentWriteAction.dispatch("approve-response").action());
        assertSame(IncidentWriteAction.RESPONSE_APPROVAL, RestIncidentWriteAction.dispatch("reject-response").action());
        assertSame(IncidentWriteAction.RESPONSE_OUTCOME, RestIncidentWriteAction.dispatch("record-response-outcome").action());
        assertSame(IncidentWriteAction.PLAYBOOK_APPLY, RestIncidentWriteAction.dispatch("apply-playbook").action());
        expectThrows(IllegalArgumentException.class, () -> RestIncidentWriteAction.dispatch("execute-response"));
        expectThrows(IllegalArgumentException.class, () -> RestIncidentWriteAction.dispatch("create"));
        expectThrows(IllegalArgumentException.class, () -> RestIncidentWriteAction.dispatch("delete"));
    }
}
