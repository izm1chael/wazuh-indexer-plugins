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

import org.opensearch.OpenSearchException;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.rest.RestStatus;

import com.wazuh.setup.utils.AuthenticatedUser;

/** Incident operations fail closed when the security plugin has not authenticated a caller. */
public final class IncidentPrincipal {
    private IncidentPrincipal() {}

    public static String require(ThreadContext context) {
        String info = context == null ? null : context.getTransient(AuthenticatedUser.USER_INFO_TRANSIENT);
        return requireUserInfo(info);
    }

    static String requireUserInfo(String info) {
        String name = AuthenticatedUser.parse(info);
        if (AuthenticatedUser.SHARED_OWNER.equals(name) || name.length() > 1024) {
            throw new OpenSearchException("Authenticated incident principal required", RestStatus.UNAUTHORIZED);
        }
        return name;
    }
}
