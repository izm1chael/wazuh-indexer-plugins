package com.wazuh.setup.incident;
import java.util.*;
import java.io.*;
public class ReplayHarness {
  public static void main(String[] args) throws Exception {
    var reader = new BufferedReader(new InputStreamReader(System.in));
    List<Map<String,Object>> rows = new ArrayList<>();
    String line;
    while ((line = reader.readLine()) != null) {
      if (line.equals("END")) {
        var result = TuningReplay.evaluate(rows);
        if (!TuningReplay.validate(result).equals(result)) throw new AssertionError("roundtrip");
        var reversed = new ArrayList<>(rows); Collections.reverse(reversed);
        if (!TuningReplay.evaluate(reversed).equals(result)) throw new AssertionError("order invariant");
        var altered = new LinkedHashMap<>(result); altered.put("total", ((Integer)result.get("total"))+1);
        try { TuningReplay.validate(altered); throw new AssertionError("tamper accepted"); }
        catch (IllegalArgumentException expected) {}
        var keys = List.of("fixture_sha256","total","malicious","benign","unknown","unknown_changed","baseline_tp","candidate_tp","baseline_fp","candidate_fp","lost_malicious","gained_malicious","removed_benign","added_benign","gate");
        System.out.println(String.join("\t",keys.stream().map(k->result.get(k).toString()).toList()));
        rows.clear();
      } else {
        var bits = line.split("\t");
        rows.add(Map.of("id",bits[0],"label",bits[1],"baseline",bits[2].equals("1"),"candidate",bits[3].equals("1")));
      }
    }
    if (!rows.isEmpty()) throw new AssertionError("incomplete input");
    try { TuningReplay.evaluate(List.of()); throw new AssertionError("empty accepted"); } catch (IllegalArgumentException expected) {}
    var one = Map.of("id","duplicate","label","malicious","baseline",true,"candidate",true);
    try { TuningReplay.evaluate(List.of(one,one)); throw new AssertionError("duplicate accepted"); } catch (IllegalArgumentException expected) {}
    try { TuningReplay.evaluate(List.of(Map.of("id","one","label","malicious","baseline",true,"candidate","true"))); throw new AssertionError("string bool accepted"); } catch (IllegalArgumentException expected) {}
    System.err.println("Java validation: 3 rejection tests; every fixture receipt roundtrip, permutation invariance and tamper rejection passed");
  }
}
