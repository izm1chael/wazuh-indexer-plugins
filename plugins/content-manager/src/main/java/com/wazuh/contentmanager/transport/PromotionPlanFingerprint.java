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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.TreeSet;

/** Fingerprint captured native plan, preserving array order and canonicalizing object keys. */
final class PromotionPlanFingerprint {
    private static final ObjectMapper JSON=new ObjectMapper();
    private PromotionPlanFingerprint(){}
    static String of(Object value){
        try{
            byte[] encoded=JSON.writeValueAsBytes(canonical(JSON.valueToTree(value),0));
            if(encoded.length>32*1024*1024)throw new IllegalArgumentException("Promotion plan exceeds fingerprint budget");
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(encoded));
        }catch(java.io.IOException|java.security.NoSuchAlgorithmException e){throw new IllegalArgumentException("Promotion plan fingerprint unavailable",e);}
    }
    private static JsonNode canonical(JsonNode node,int depth){
        if(depth>128)throw new IllegalArgumentException("Promotion plan exceeds nesting budget");
        if(node.isObject()){
            var keys=new TreeSet<String>();node.fieldNames().forEachRemaining(keys::add);
            ObjectNode result=JSON.createObjectNode();
            for(String key:keys)result.set(key,canonical(node.get(key),depth+1));
            return result;
        }
        if(node.isArray()){
            var result=JSON.createArrayNode();
            for(JsonNode child:node)result.add(canonical(child,depth+1));
            return result;
        }
        return node;
    }
    static boolean approved(String configured,String actual){
        return configured!=null&&configured.matches("[a-f0-9]{64}")&&configured.equals(actual);
    }
}
