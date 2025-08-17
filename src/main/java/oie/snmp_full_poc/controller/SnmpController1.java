package oie.snmp_full_poc.controller;

import oie.snmp_full_poc.service.SnmpService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivDES;
import org.snmp4j.smi.OID;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/snmp")
public class SnmpController1 {

    private final SnmpService snmpService;

    public SnmpController1(SnmpService snmpService) {
        this.snmpService = snmpService;
    }

    @PostMapping("/get")
    public ResponseEntity<?> get(@RequestBody Map<String, Object> body) {
        try {
            String host = (String) body.get("host");
            int port = (int) body.getOrDefault("port", 161);
            String username = (String) body.get("username");
            String authPass = (String) body.get("authPass"); // optional
            String privPass = (String) body.get("privPass"); // optional
            String oid = (String) body.get("oid");

            // choose OID constants - map strings to OIDs as needed
            OID authOid = body.getOrDefault("auth", "SHA").equals("MD5") ? AuthMD5.ID : AuthSHA.ID;
            OID privOid = body.getOrDefault("priv", "AES").equals("DES") ? PrivDES.ID : PrivAES128.ID;

            String value = snmpService.get(host, port, username, authOid, authPass, privOid, privPass, oid);
            return ResponseEntity.ok(Map.of("value", value));
        } catch (Exception ex) {
            return ResponseEntity.status(500).body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/walk")
    public ResponseEntity<?> walk(@RequestBody Map<String, Object> body) {
        try {
            String host = (String) body.get("host");
            int port = (int) body.getOrDefault("port", 161);
            String username = (String) body.get("username");
            String authPass = (String) body.get("authPass"); // optional
            String privPass = (String) body.get("privPass"); // optional
            String baseOid = (String) body.getOrDefault("baseOid", "1.3.6.1.2.1.1");

            OID authOid = body.getOrDefault("auth", "SHA").equals("MD5") ? AuthMD5.ID : AuthSHA.ID;
            OID privOid = body.getOrDefault("priv", "AES").equals("DES") ? PrivDES.ID : PrivAES128.ID;

            List<String> result = snmpService.walk(host, port, username, authOid, authPass, privOid, privPass, baseOid);
            return ResponseEntity.ok(result);
        } catch (Exception ex) {
            return ResponseEntity.status(500).body(Map.of("error", ex.getMessage()));
        }
    }
}

