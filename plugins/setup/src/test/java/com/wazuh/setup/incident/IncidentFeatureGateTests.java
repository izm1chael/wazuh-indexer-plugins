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
package com.wazuh.setup.incident;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

import com.wazuh.setup.settings.PluginSettings;

public class IncidentFeatureGateTests extends OpenSearchTestCase {
    public void testDisabledByDefault() {
        assertFalse(PluginSettings.INCIDENTS_ENABLED.get(Settings.EMPTY));
        assertFalse(PluginSettings.BEHAVIOUR_ENABLED.get(Settings.EMPTY));
        assertFalse(PluginSettings.RULE_BEHAVIOUR_ENABLED.get(Settings.EMPTY));
        assertTrue(PluginSettings.RULE_BEHAVIOUR_ENABLED.get(Settings.builder().put("plugins.setup.incidents.behaviour.rule.enabled", true).build()));
        assertTrue(PluginSettings.BEHAVIOUR_ENABLED.get(Settings.builder().put("plugins.setup.incidents.behaviour.enabled", true).build()));
        assertFalse(PluginSettings.WORKFLOWS_ENABLED.get(Settings.EMPTY));
        assertTrue(PluginSettings.WORKFLOWS_ENABLED.get(Settings.builder().put("plugins.setup.incidents.workflows.enabled", true).build()));
        assertTrue(PluginSettings.INCIDENTS_ENABLED.get(Settings.builder()
                .put("plugins.setup.incidents.enabled", true).build()));
    }
}
