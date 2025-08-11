package oie.snmp_full_poc.controller;

import oie.snmp_full_poc.service.SnmpV3ManagerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/snmp")
public class SnmpController {

    private final SnmpV3ManagerService snmpService;

    public SnmpController(SnmpV3ManagerService snmpService) {
        this.snmpService = snmpService;
    }


    @GetMapping("/get")
    public ResponseEntity<?> get(
            @RequestParam String host,
            @RequestParam(defaultValue = "161") int port,
            @RequestParam String user,
            @RequestParam String auth,
            @RequestParam String priv,
            @RequestParam String oid
    ) throws Exception {
        String value = snmpService.getAsString(host, port, user, auth, priv, oid);
        return ResponseEntity.ok(value);
    }


    @PostMapping("/set")
    public ResponseEntity<?> set(
            @RequestParam String host,
            @RequestParam(defaultValue = "161") int port,
            @RequestParam String user,
            @RequestParam String auth,
            @RequestParam String priv,
            @RequestParam String oid,
            @RequestParam String value
    ) throws Exception {
        snmpService.setString(host, port, user, auth, priv, oid, value);
        return ResponseEntity.ok("OK");
    }
}
