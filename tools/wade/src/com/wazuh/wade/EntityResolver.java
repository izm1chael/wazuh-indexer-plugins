// SPDX-License-Identifier: AGPL-3.0-or-later
package com.wazuh.wade;

import java.time.Instant;
import java.util.*;

/** Point-in-time alias resolution from trusted, scoped identity observations. */
public final class EntityResolver {
    private EntityResolver() {}
    public enum Type { USER, HOST, SERVICE, CLOUD_PRINCIPAL }
    public enum Kind { IMMUTABLE_ID, VERIFIED_ALIAS, IP_ADDRESS }
    public enum Status { RESOLVED, UNKNOWN, AMBIGUOUS }
    public record Key(String tenant, Type type, String namespace, String value, Kind kind) {
        public Key { key(tenant); Objects.requireNonNull(type); key(namespace); key(value); Objects.requireNonNull(kind); }
    }
    public record Binding(Key alias, String canonicalId, Instant validFrom, Instant validUntil,
                          Instant availableAt, String provenance) {
        public Binding {
            Objects.requireNonNull(alias); key(canonicalId); Objects.requireNonNull(validFrom);
            Objects.requireNonNull(availableAt); key(provenance);
            if (validUntil != null && !validFrom.isBefore(validUntil)) throw new IllegalArgumentException("invalid validity");
        }
    }
    public record Result(Status status,String canonicalId,List<String> provenance,String reason) {
        public Result { provenance=List.copyOf(provenance); }
    }
    public static Result resolve(Key alias,Instant eventTime,Instant asOf,List<Binding> bindings) {
        Objects.requireNonNull(alias); Objects.requireNonNull(eventTime); Objects.requireNonNull(asOf); Objects.requireNonNull(bindings);
        if (eventTime.isAfter(asOf)) throw new IllegalArgumentException("future event");
        if (bindings.size()>10000) return unknown("INPUT_LIMIT");
        if (alias.kind()==Kind.IP_ADDRESS) return unknown("IP_ONLY_NOT_IDENTITY");
        Map<String,Set<String>> candidates=new TreeMap<>();
        for (Binding b:bindings) {
            if (!alias.tenant().equals(b.alias().tenant())) return unknown("SCOPE_MISMATCH");
            if (!alias.equals(b.alias()) || b.availableAt().isAfter(asOf) || eventTime.isBefore(b.validFrom())
                || (b.validUntil()!=null && !eventTime.isBefore(b.validUntil()))) continue;
            candidates.computeIfAbsent(b.canonicalId(),k->new TreeSet<>()).add(b.provenance());
        }
        if (candidates.isEmpty()) return unknown("NO_VALID_BINDING");
        if (candidates.size()>1) return new Result(Status.AMBIGUOUS,null,List.of(),"MULTIPLE_BINDINGS");
        var only=candidates.entrySet().iterator().next();
        return new Result(Status.RESOLVED,only.getKey(),List.copyOf(only.getValue()),"VALID_BINDING");
    }
    private static Result unknown(String why) { return new Result(Status.UNKNOWN,null,List.of(),why); }
    private static void key(String x) {
        if(x==null||x.isBlank()||x.length()>1024) throw new IllegalArgumentException("invalid key");
    }
}
