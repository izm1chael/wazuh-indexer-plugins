// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** Local qualification bridge for the bounded temporal reference engine. */
public final class NativeTemporalBridge {
    private NativeTemporalBridge() {}
    private static String read(BufferedReader in) throws IOException {
        String line = in.readLine();
        if (line == null || line.length() > 8192) throw new IOException("invalid frame");
        return new String(Base64.getUrlDecoder().decode(line), StandardCharsets.UTF_8);
    }
    private static void emit(String value) {
        System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8)));
    }
    public static void main(String[] args) throws IOException {
        try (var in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            if (!read(in).equals("wade-temporal-bridge-v1")) throw new IOException("protocol");
            String scope = read(in);
            var mode = TemporalCorrelation.Mode.valueOf(read(in));
            var span = Duration.ofSeconds(Long.parseLong(read(in)));
            int limit = Integer.parseInt(read(in)), stages = Integer.parseInt(read(in));
            if (stages < 2 || stages > 16) throw new IOException("stage limit");
            List<String> names = new ArrayList<>();
            for (int i = 0; i < stages; i++) names.add(Integer.toString(i));
            var rule = new TemporalCorrelation.Rule(names, mode, span, limit);
            Instant start = Instant.parse(read(in)), end = Instant.parse(read(in));
            int count = Integer.parseInt(read(in));
            if (count < 0 || count > 10000) throw new IOException("input limit");
            List<TemporalCorrelation.Event> events = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                String ref = read(in); Instant time = Instant.parse(read(in));
                int mask = Integer.parseInt(read(in));
                if (mask < 1 || mask >= (1 << stages)) throw new IOException("invalid stage mask");
                Set<String> matched = new HashSet<>();
                for (int j = 0; j < stages; j++) if ((mask & (1 << j)) != 0) matched.add(names.get(j));
                events.add(new TemporalCorrelation.Event(scope, ref, time, matched));
            }
            if (in.readLine() != null) throw new IOException("trailing input");
            var result = TemporalCorrelation.evaluate(rule, scope, start, end, end, true, events);
            emit(result.status().name()); emit(result.reason());
            for (var event : result.evidence()) emit(event.source());
        }
    }
}
