// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

/** Offline count-rule replay; source authority and coverage are adapter responsibilities. */
public final class ReplayEngine {
    private ReplayEngine() {}
    public record Definition(String tenant, DetectionKernel.Rule rule, String selectorDigest) {
        public Definition {
            key(tenant); Objects.requireNonNull(rule); digestKey(selectorDigest);
        }
        public String digest() {
            return hash("wade-rule-v1", tenant, rule.id(), rule.version(), rule.mode().name(),
                Integer.toString(rule.threshold()), Integer.toString(rule.maxInputs()), selectorDigest);
        }
    }
    public record Version(String tenant, String id, String version) {
        public Version { key(tenant); key(id); key(version); }
    }
    /** In-memory reference registry; versions are immutable, even when a selector changes. */
    public static final class Registry {
        private final Map<Version,Definition> definitions = new HashMap<>();
        public synchronized Definition register(Definition d) {
            Objects.requireNonNull(d);
            Version v = new Version(d.tenant(),d.rule().id(),d.rule().version());
            Definition old = definitions.get(v);
            if (old != null && !old.equals(d)) throw new IllegalStateException("version conflict");
            if (old != null) return old;
            if (definitions.size() >= 10000) throw new IllegalStateException("registry limit");
            definitions.put(v,d); return d;
        }
        public synchronized Definition require(Version v) {
            Definition d = definitions.get(v);
            if (d == null) throw new IllegalArgumentException("unknown rule revision");
            return d;
        }
    }
    public record Observed(DetectionKernel.Evidence evidence, Instant availableAt) {
        public Observed { Objects.requireNonNull(evidence); Objects.requireNonNull(availableAt); }
    }
    public record Case(String id, DetectionKernel.Scope scope, DetectionKernel.Window window,
                       Instant asOf, Instant watermark, DetectionKernel.Coverage coverage,
                       DetectionQuality.Label label, List<Observed> inputs) {
        public Case {
            key(id); Objects.requireNonNull(scope); Objects.requireNonNull(window); Objects.requireNonNull(asOf);
            Objects.requireNonNull(watermark); Objects.requireNonNull(coverage); Objects.requireNonNull(label);
            if (watermark.isAfter(asOf) || inputs.size() > 10000) throw new IllegalArgumentException("invalid replay boundary");
            inputs = List.copyOf(inputs);
        }
    }
    public record Outcome(String caseId, DetectionKernel.Status status, String reason,
                          String inputDigest, DetectionKernel.Finding finding) {}
    public record Report(String ruleDigest, String receipt, List<Outcome> outcomes, DetectionQuality.Metrics metrics) {
        public Report { outcomes = List.copyOf(outcomes); }
    }
    public static Report run(Registry registry, Version version, List<Case> cases) {
        Definition d = registry.require(version); Objects.requireNonNull(cases);
        if (cases.size() > 1000) throw new IllegalArgumentException("case limit");
        Map<String,Case> unique = new TreeMap<>(); long total = 0;
        for (Case c : cases) {
            if (!d.tenant().equals(c.scope().tenant())) throw new IllegalArgumentException("foreign scope");
            if ((total += c.inputs().size()) > 100000) throw new IllegalArgumentException("replay input limit");
            if (unique.putIfAbsent(c.id(),c) != null) throw new IllegalArgumentException("duplicate case ID");
        }
        List<Outcome> outcomes = new ArrayList<>(); List<DetectionQuality.Case> metrics = new ArrayList<>();
        List<String> receipt = new ArrayList<>(List.of("wade-replay-v1", d.digest()));
        for (Case c : unique.values()) {
            List<DetectionKernel.Evidence> admitted = new ArrayList<>();
            List<String> inputHashes = new ArrayList<>();
            for (Observed o : c.inputs()) {
                var e = o.evidence();
                if (!c.scope().equals(e.scope())) throw new IllegalArgumentException("foreign evidence");
                if (o.availableAt().isAfter(c.asOf())) continue;
                if (e.eventTime().isAfter(c.asOf())) throw new IllegalArgumentException("future event");
                admitted.add(e);
                inputHashes.add(hash(e.source().index(),e.source().documentId(),e.eventTime().toString(),
                    o.availableAt().toString(),e.distinctValue()==null?"absent":"present",
                    e.distinctValue()==null?"":e.distinctValue()));
            }
            // Preserve multiplicity for resource-limit outcomes while canonicalizing input order.
            Collections.sort(inputHashes);
            String inputDigest = hash(inputHashes.toArray(String[]::new));
            var result = DetectionKernel.evaluate(d.rule(),c.scope(),c.window(),c.watermark(),c.coverage(),admitted);
            Outcome o = new Outcome(c.id(),result.status(),result.reason(),inputDigest,result.finding()); outcomes.add(o);
            DetectionQuality.Outcome mapped = switch (o.status()) {
                case MATCH -> DetectionQuality.Outcome.MATCH;
                case NO_MATCH -> DetectionQuality.Outcome.NO_MATCH;
                case UNKNOWN, NOT_READY -> DetectionQuality.Outcome.UNKNOWN;
            };
            metrics.add(new DetectionQuality.Case(c.id(),c.label(),mapped));
            receipt.add(hash(c.id(),c.scope().tenant(),c.scope().entityType(),c.scope().entityId(),
                c.window().start().toString(),c.window().end().toString(),c.asOf().toString(),c.watermark().toString(),
                c.coverage().name(),c.label().name(),Integer.toString(admitted.size()),inputDigest,o.status().name(),o.reason(),
                o.finding()==null?"":o.finding().id(),o.finding()==null?"":o.finding().evidenceDigest()));
        }
        return new Report(d.digest(),hash(receipt.toArray(String[]::new)),outcomes,DetectionQuality.measure(metrics));
    }
    static void key(String s) {
        if (s == null || s.isBlank() || s.length() > 1024 || !StandardCharsets.UTF_8.newEncoder().canEncode(s))
            throw new IllegalArgumentException("invalid key");
    }
    static void digestKey(String s) {
        if (s == null || !s.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid digest");
    }
    static String hash(String... fields) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            for (String field : fields) {
                byte[] b = field.getBytes(StandardCharsets.UTF_8);
                d.update(ByteBuffer.allocate(4).putInt(b.length).array()); d.update(b);
            }
            return HexFormat.of().formatHex(d.digest());
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
