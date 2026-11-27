// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Offline, bounded reference kernel. Input is already authorized and rule-matched. */
public final class DetectionKernel {
    private DetectionKernel() {}

    public enum Mode { EVENT_COUNT, DISTINCT_VALUE_COUNT }
    public enum Coverage { COMPLETE, UNKNOWN }
    public enum Status { NOT_READY, UNKNOWN, NO_MATCH, MATCH }

    public record Scope(String tenant, String entityType, String entityId) {
        public Scope {
            token(tenant); token(entityType); token(entityId);
        }
    }

    public record Rule(String id, String version, Mode mode, int threshold, int maxInputs) {
        public Rule {
            token(id); token(version); Objects.requireNonNull(mode);
            if (threshold < 1 || maxInputs < threshold || maxInputs > 10000) {
                throw new IllegalArgumentException("invalid rule limits");
            }
        }
    }

    /** Half-open event-time window. The watermark is a caller-supplied completeness boundary. */
    public record Window(Instant start, Instant end) {
        public Window {
            Objects.requireNonNull(start); Objects.requireNonNull(end);
            if (!start.isBefore(end) || Duration.between(start, end).compareTo(Duration.ofDays(31)) > 0) {
                throw new IllegalArgumentException("invalid window");
            }
        }
        boolean contains(Instant t) { return !t.isBefore(start) && t.isBefore(end); }
    }

    public record Source(String index, String documentId) {
        public Source { token(index); token(documentId); }
    }

    public record Evidence(Scope scope, Source source, Instant eventTime, String distinctValue) {
        public Evidence {
            Objects.requireNonNull(scope); Objects.requireNonNull(source); Objects.requireNonNull(eventTime);
            if (distinctValue != null) token(distinctValue);
        }
    }

    /** ID is stable for a rule revision, scope and window; evidence digest identifies the snapshot. */
    public record Finding(String id, String evidenceDigest, Scope scope, Rule rule, Window window,
                          int observedCount, List<Source> sources) {
        public Finding { sources = List.copyOf(sources); }
    }

    public record Evaluation(Status status, String reason, Finding finding) {
        public Evaluation {
            Objects.requireNonNull(status); Objects.requireNonNull(reason);
            if ((status == Status.MATCH) != (finding != null)) {
                throw new IllegalArgumentException("finding/status mismatch");
            }
        }
    }

    private static final Comparator<Evidence> ORDER = Comparator
        .comparing(Evidence::eventTime)
        .thenComparing(e -> e.source().index())
        .thenComparing(e -> e.source().documentId());

    public static Evaluation evaluate(Rule rule, Scope scope, Window window, Instant watermark,
                                      Coverage coverage, List<Evidence> inputs) {
        Objects.requireNonNull(rule); Objects.requireNonNull(scope); Objects.requireNonNull(window);
        Objects.requireNonNull(watermark); Objects.requireNonNull(coverage); Objects.requireNonNull(inputs);
        // Never publish a partial finding or infer absence from incomplete input.
        if (inputs.size() > rule.maxInputs()) return result(Status.UNKNOWN, "INPUT_LIMIT");
        Map<Source, Evidence> seen = new HashMap<>();
        for (Evidence e : inputs) {
            Objects.requireNonNull(e);
            if (!scope.equals(e.scope())) return result(Status.UNKNOWN, "SCOPE_MISMATCH");
            if (!window.contains(e.eventTime())) continue;
            Evidence prior = seen.putIfAbsent(e.source(), e);
            if (prior != null && !prior.equals(e)) return result(Status.UNKNOWN, "CONFLICTING_SOURCE");
        }
        if (watermark.isBefore(window.end())) return result(Status.NOT_READY, "WINDOW_OPEN");
        if (coverage != Coverage.COMPLETE) return result(Status.UNKNOWN, "INCOMPLETE_COVERAGE");

        List<Evidence> sorted = new ArrayList<>(seen.values());
        sorted.sort(ORDER);
        int count = sorted.size();
        if (rule.mode() == Mode.DISTINCT_VALUE_COUNT) {
            Set<String> values = new HashSet<>();
            for (Evidence e : sorted) {
                if (e.distinctValue() == null) return result(Status.UNKNOWN, "MISSING_DISTINCT_VALUE");
                values.add(e.distinctValue());
            }
            count = values.size();
        }
        if (count < rule.threshold()) return result(Status.NO_MATCH, "BELOW_THRESHOLD");

        MessageDigest id = sha256();
        add(id, "wade-finding-v1", scope.tenant(), scope.entityType(), scope.entityId(),
            rule.id(), rule.version(), window.start().toString(), window.end().toString());
        MessageDigest snapshot = sha256();
        add(snapshot, "wade-evidence-v1", rule.mode().name(), Integer.toString(rule.threshold()));
        for (Evidence e : sorted) {
            add(snapshot, e.source().index(), e.source().documentId(), e.eventTime().toString(),
                e.distinctValue() == null ? "absent" : "present",
                e.distinctValue() == null ? "" : e.distinctValue());
        }
        Finding finding = new Finding(hex(id), hex(snapshot), scope, rule, window, count,
            sorted.stream().map(Evidence::source).toList());
        return new Evaluation(Status.MATCH, "THRESHOLD_MET", finding);
    }

    private static Evaluation result(Status status, String reason) { return new Evaluation(status, reason, null); }

    private static void token(String value) {
        if (value == null || value.isBlank() || value.length() > 1024
            || !StandardCharsets.UTF_8.newEncoder().canEncode(value)) {
            throw new IllegalArgumentException("invalid identifier/value");
        }
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    // Length framing avoids delimiter ambiguity. No raw evidence values are emitted in findings.
    private static void add(MessageDigest digest, String... values) {
        for (String value : values) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
            digest.update(bytes);
        }
    }

    private static String hex(MessageDigest digest) { return HexFormat.of().formatHex(digest.digest()); }
}
