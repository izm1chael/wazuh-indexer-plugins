// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade.plugin;

import org.opensearch.plugins.Plugin;

/** Intentionally inert packaging entrypoint. No settings, handlers, threads or cluster writes. */
public final class WadePlugin extends Plugin {
    public WadePlugin() {}
}
