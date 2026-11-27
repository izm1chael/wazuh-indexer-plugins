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

import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.rest.RestStatus;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Persistent owner-driven workflows. Reuses actual task and response records; no external calls. */
final class IncidentWorkflowRuns {
    static final int MAX_RUNS = 10;
    private static final Set<String> TERMINAL = Set.of("completed", "failed", "cancelled");
    private static final Set<String> RESPONSE_TERMINAL = Set.of("rejected", "cancelled", "reported_completed", "reported_failed", "reported_not_performed");
    private static final Set<String> RESPONSE_FAILURE = Set.of("rejected", "cancelled", "reported_failed", "reported_not_performed");
    private static final String PREPARE = "Confirm target, scope and business impact before requesting response";
    private static final String REVIEW = "Review response evidence and document remaining risk; completion is analyst-attested";
    private static final Set<String> FIELDS = Set.of("id", "template_id", "version", "scope", "reason", "steps");
    private static final Set<String> STEP = Set.of("stage", "revision", "actor", "at", "reference", "observation");
    private IncidentWorkflowRuns() {}

    static String type(String template) {
        return switch (template) {
            case "vulnerability_investigation" -> "scan_vulnerability";
            case "evidence_collection" -> "collect_evidence";
            default -> throw invalid("Unknown workflow template");
        };
    }
    static String text(Object value, int limit) {
        if (!(value instanceof String s) || s.isBlank() || s.length() > limit || !s.equals(s.trim()) || s.chars().anyMatch(Character::isISOControl))
            throw invalid("Invalid workflow text");
        return s;
    }
    private static String scope(String template, Object raw) {
        String value = text(raw, 512);
        if ("scan_vulnerability".equals(type(template))) IncidentResponses.scanScope(value);
        return value;
    }
    private static Map<String,Object> step(String stage, int revision, String actor, String at, String reference, String observation) {
        return Map.of("stage", stage, "revision", revision, "actor", actor, "at", at, "reference", reference, "observation", observation);
    }
    @SuppressWarnings("unchecked")
    private static List<Map<String,Object>> steps(Map<String,Object> run) { return (List<Map<String,Object>>) run.get("steps"); }
    private static Map<String,Object> last(Map<String,Object> run) { var s = steps(run); return s.get(s.size()-1); }
    private static String stage(Map<String,Object> run) { return (String) last(run).get("stage"); }
    private static Map<String,Object> find(List<Map<String,Object>> rows, Object id) {
        var matches = rows.stream().filter(row -> id.equals(row.get("id"))).toList();
        if (matches.size() != 1) throw conflict("Workflow reference unavailable or ambiguous");
        return matches.get(0);
    }
    private static boolean taskMatches(Map<String,Object> task, Map<String,Object> step, String title) {
        if (!title.equals(task.get("title")) || !step.get("actor").equals(task.get("created_by")) || !step.get("at").equals(task.get("created_at"))) return false;
        if ("open".equals(task.get("status"))) return task.get("completed_by") == null && task.get("completed_at") == null;
        if (!"completed".equals(task.get("status"))) return false;
        text(task.get("completed_by"),1024);
        return !Instant.parse(text(task.get("completed_at"),64)).isBefore(Instant.parse((String)step.get("at")));
    }

    static List<Map<String,Object>> runs(Map<String,Object> source) {
        if (!(source.getOrDefault("workflow_runs", List.of()) instanceof List<?> raw) || raw.size() > MAX_RUNS)
            throw conflict("Invalid workflow history");
        var result = new ArrayList<Map<String,Object>>();
        if (raw.isEmpty()) return result;
        var tasks = IncidentInvestigationService.projectTasks(source);
        var responses = IncidentResponses.project(source);
        var revisions = new HashSet<Integer>();
        int priorEnd = 0, active = 0;
        for (Object item : raw) {
            if (!(item instanceof Map<?,?> row) || !row.keySet().equals(FIELDS) || !Integer.valueOf(1).equals(row.get("version")) ||
                    !(row.get("steps") instanceof List<?> entries) || entries.isEmpty() || entries.size() > 4) throw conflict("Invalid workflow record");
            String template = text(row.get("template_id"),64), target = scope(template,row.get("scope")), reason = text(row.get("reason"),2048);
            String id = text(row.get("id"),64);
            var events = new ArrayList<Map<String,Object>>();
            String previous = "", responseState = null;
            int prior = 0; Instant before = null; Map<String,Object> response = null;
            for (Object entry : entries) {
                if (!(entry instanceof Map<?,?> event) || !event.keySet().equals(STEP) ||
                        !(event.get("revision") instanceof Integer rev) || rev <= prior || rev > (Integer) source.get("revision") ||
                        !revisions.add(rev)) throw conflict("Invalid workflow transition revision");
                String phase = text(event.get("stage"),32), actor = text(event.get("actor"),1024), at = text(event.get("at"),64);
                Instant instant = Instant.parse(at);
                if (before != null && instant.isBefore(before)) throw conflict("Invalid workflow chronology");
                if (!(event.get("reference") instanceof String ref) || ref.length() > 64 ||
                        !(event.get("observation") instanceof String observation) || observation.length() > 2048)
                    throw conflict("Invalid workflow transition");
                var normalized = step(phase,rev,actor,at,ref,observation);
                String expected = source.get("id") + ":" + rev;
                switch (phase) {
                    case "prepare":
                        if (!previous.isEmpty() || !id.equals(expected) || rev <= priorEnd || active != 0 || !expected.equals(ref) ||
                                !"started".equals(observation) || !taskMatches(find(tasks,ref),normalized,PREPARE)) throw conflict("Invalid preparation step");
                        break;
                    case "response":
                        if (!"prepare".equals(previous) || !expected.equals(ref) || !"task_completed".equals(observation))
                            throw conflict("Invalid response step");
                        response = find(responses,ref);
                        if (!type(template).equals(response.get("type")) || !target.equals(response.get("scope")) || !reason.equals(response.get("reason")) ||
                                !actor.equals(response.get("requested_by")) || !at.equals(response.get("requested_at"))) throw conflict("Invalid workflow response linkage");
                        responseState = (String) response.get("state"); break;
                    case "review":
                        if (!"response".equals(previous) || !"reported_completed".equals(observation) || !observation.equals(responseState) ||
                                !expected.equals(ref) || !taskMatches(find(tasks,ref),normalized,REVIEW)) throw conflict("Invalid review step");
                        break;
                    case "completed":
                        if (!"review".equals(previous) || !ref.isEmpty() || !"task_completed".equals(observation)) throw conflict("Invalid completion step");
                        break;
                    case "failed":
                        if (!"response".equals(previous) || !ref.isEmpty() || !RESPONSE_FAILURE.contains(observation) ||
                                !observation.equals(responseState)) throw conflict("Invalid failed step");
                        break;
                    case "cancelled":
                        if (!Set.of("prepare","response","review").contains(previous) || !ref.isEmpty() ||
                                !observation.equals(text(observation,2048)) || ("response".equals(previous) && !RESPONSE_TERMINAL.contains(responseState)))
                            throw conflict("Invalid cancelled step");
                        break;
                    default: throw conflict("Unknown workflow step");
                }
                events.add(normalized); previous = phase; prior = rev; before = instant;
            }
            priorEnd = prior;
            if (!TERMINAL.contains(previous) && ++active > 1) throw conflict("Multiple active workflows");
            result.add(Map.of("id",id,"template_id",template,"version",1,"scope",target,"reason",reason,"steps",events));
        }
        return result;
    }

    static void requireNoOutstanding(Map<String,Object> source) {
        if (runs(source).stream().anyMatch(run -> !TERMINAL.contains(stage(run)))) throw conflict("Finish or cancel active workflow before closing");
    }

    static List<Map<String,Object>> view(Map<String,Object> source) {
        var tasks = IncidentInvestigationService.projectTasks(source); var responses = IncidentResponses.project(source);
        var result = new ArrayList<Map<String,Object>>();
        for (var run : runs(source)) {
            var out = new LinkedHashMap<>(run);
            var event = last(run); String phase = stage(run);
            String observed = "terminal";
            if ("prepare".equals(phase) || "review".equals(phase)) observed = (String) find(tasks,event.get("reference")).get("status");
            if ("response".equals(phase)) observed = (String) find(responses,event.get("reference")).get("state");
            out.put("observed_state",observed);
            out.put("can_advance", ("prepare".equals(phase) || "review".equals(phase)) && "completed".equals(observed) ||
                    "response".equals(phase) && RESPONSE_TERMINAL.contains(observed));
            out.put("can_cancel", Set.of("prepare","review").contains(phase) || "response".equals(phase) && RESPONSE_TERMINAL.contains(observed));
            result.add(out);
        }
        return result;
    }

    static String apply(Map<String,Object> next, Map<String,Object> changes, IncidentMutation.Operation op,
            Map<String,Object> input, String actor, String now, int revision) {
        if (!Set.of("triaging","active").contains(next.get("status")) || next.get("handover") != null)
            throw conflict("Assigned investigation without pending handover required");
        var runs = runs(next);
        Map<String,Object> before = null, after;
        String kind;
        if (op == IncidentMutation.Operation.START_WORKFLOW) {
            if (!input.keySet().equals(Set.of("template_id","version","scope","reason")) || !Integer.valueOf(1).equals(input.get("version")))
                throw invalid("Exact workflow definition required");
            String template = text(input.get("template_id"),64), target = scope(template,input.get("scope")), reason = text(input.get("reason"),2048);
            if (runs.size() >= MAX_RUNS || runs.stream().anyMatch(run -> !TERMINAL.contains(stage(run)))) throw conflict("Workflow capacity or active workflow");
            String id = next.get("id") + ":" + revision;
            IncidentTasks.apply(next,changes,IncidentMutation.Operation.CREATE_TASK,Map.of("title",PREPARE),actor,now,revision);
            after = Map.of("id",id,"template_id",template,"version",1,"scope",target,"reason",reason,"steps",List.of(step("prepare",revision,actor,now,id,"started")));
            runs.add(after); kind = "workflow_started";
        } else {
            boolean cancel = op == IncidentMutation.Operation.CANCEL_WORKFLOW;
            if (!input.keySet().equals(cancel ? Set.of("run_id","reason") : Set.of("run_id"))) throw invalid("Exact workflow operation required");
            String id = text(input.get("run_id"),64);
            before = find(runs,id); String phase = stage(before);
            if (TERMINAL.contains(phase)) throw conflict("Workflow already terminal");
            var current = view(next).stream().filter(row -> id.equals(row.get("id"))).findFirst().orElseThrow();
            if (!Boolean.TRUE.equals(current.get(cancel ? "can_cancel" : "can_advance"))) throw conflict("Workflow checkpoint not satisfied");
            var events = new ArrayList<>(steps(before));
            String reference = next.get("id") + ":" + revision;
            if (cancel) {
                events.add(step("cancelled",revision,actor,now,"",text(input.get("reason"),2048)));
                kind = "workflow_cancelled";
            } else if ("prepare".equals(phase)) {
                IncidentResponses.apply(next,changes,IncidentMutation.Operation.REQUEST_RESPONSE,Map.of("type",type((String)before.get("template_id")),
                        "scope",before.get("scope"),"reason",before.get("reason")),actor,now,revision);
                events.add(step("response",revision,actor,now,reference,"task_completed"));
                kind = "workflow_advanced";
            } else if ("response".equals(phase)) {
                String observed = (String) current.get("observed_state");
                if ("reported_completed".equals(observed)) {
                    IncidentTasks.apply(next,changes,IncidentMutation.Operation.CREATE_TASK,Map.of("title",REVIEW),actor,now,revision);
                    events.add(step("review",revision,actor,now,reference,observed)); kind = "workflow_advanced";
                } else {
                    events.add(step("failed",revision,actor,now,"",observed)); kind = "workflow_failed";
                }
            } else {
                events.add(step("completed",revision,actor,now,"","task_completed")); kind = "workflow_completed";
            }
            after = new LinkedHashMap<>(before); after.put("steps",events);
            runs.set(runs.indexOf(before),after);
        }
        next.put("workflow_runs",runs);
        var change = new LinkedHashMap<String,Object>(); change.put("before",before); change.put("after",after);
        changes.put("workflow_run",change);
        changes.put("workflow_id",Map.of("before",after.get("id"),"after",after.get("id")));
        changes.put("workflow_stage",Map.of("before",before == null ? "none" : stage(before),"after",stage(after)));
        return kind;
    }
    private static OpenSearchStatusException invalid(String message) { return new OpenSearchStatusException(message, RestStatus.BAD_REQUEST); }
    private static OpenSearchStatusException conflict(String message) { return new OpenSearchStatusException(message, RestStatus.CONFLICT); }
}
