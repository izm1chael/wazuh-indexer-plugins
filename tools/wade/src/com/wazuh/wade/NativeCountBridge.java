// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import static com.wazuh.wade.DetectionKernel.*;

/** Local stdin/stdout harness, never a remotely accessible process or scheduler. */
public final class NativeCountBridge {
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private NativeCountBridge() {}
    private static String read(BufferedReader reader) throws IOException {
        String line = reader.readLine();
        if (line == null || line.length() > 8192) throw new IOException("invalid bridge frame");
        return new String(DECODER.decode(line), StandardCharsets.UTF_8);
    }
    private static void emit(String value) {
        System.out.println(ENCODER.encodeToString(value.getBytes(StandardCharsets.UTF_8)));
    }
    public static void main(String[] args) throws IOException {
        try (var in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            if (!read(in).equals("wade-count-bridge-v1")) throw new IOException("unsupported protocol");
            Scope scope = new Scope(read(in), read(in), read(in));
            Rule rule = new Rule(read(in), read(in), Mode.valueOf(read(in)),
                Integer.parseInt(read(in)), Integer.parseInt(read(in)));
            Window window = new Window(Instant.parse(read(in)), Instant.parse(read(in)));
            Instant watermark = Instant.parse(read(in));
            Coverage coverage = Coverage.valueOf(read(in));
            int count = Integer.parseInt(read(in));
            if (count < 0 || count > 10000) throw new IOException("input limit");
            List<Evidence> evidence = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                Source source = new Source(read(in), read(in));
                Instant timestamp = Instant.parse(read(in));
                String value = read(in);
                evidence.add(new Evidence(scope, source, timestamp, value.isEmpty() ? null : value));
            }
            if (in.readLine() != null) throw new IOException("trailing input");
            Evaluation result = evaluate(rule, scope, window, watermark, coverage, evidence);
            emit(result.status().name()); emit(result.reason());
            if (result.finding() != null) {
                Finding f = result.finding();
                emit(f.id()); emit(f.evidenceDigest()); emit(Integer.toString(f.observedCount()));
                emit(Integer.toString(f.sources().size()));
                for (Source s : f.sources()) { emit(s.index()); emit(s.documentId()); }
            }
        }
    }
}
