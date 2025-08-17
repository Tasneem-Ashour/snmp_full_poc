package oie.snmp_full_poc.controller;

import oie.snmp_full_poc.dto.SnmpResponse;
import oie.snmp_full_poc.error.ErrorResponse;
import oie.snmp_full_poc.service.SnmpV3ManagerService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/snmp")
public class SnmpController {

    private final SnmpV3ManagerService snmpService;

    public SnmpController(SnmpV3ManagerService snmpService) {
        this.snmpService = snmpService;
    }

    /**
     * GET endpoint example:
     * /api/snmp/get?host=127.0.0.1&port=161&user=myUser&authPass=authPass&privPass=privPass&authProtocol=SHA&privProtocol=AES128&oid=1.3.6.1.2.1.1.1.0
     */
//    @GetMapping("/get")
//    public ResponseEntity<?> get(
//            @RequestParam String host,
//            @RequestParam(defaultValue = "161") int port,
//            @RequestParam String user,
//            @RequestParam String authPass,
//            @RequestParam String privPass,
//            @RequestParam(defaultValue = "SHA") String authProtocol,
//            @RequestParam(defaultValue = "AES128") String privProtocol,
//            @RequestParam String oid
//    ) {
//        try {
//            SnmpResponse resp = snmpService.get(host, port, user, authPass, privPass, authProtocol, privProtocol, oid);
//            return ResponseEntity.ok(resp);
//        } catch (IllegalArgumentException iae) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("Invalid parameters", iae.getMessage()));
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorResponse("SNMP error", e.getMessage()));
//        }
//    }
//
//
//    /**
//     * POST /api/snmp/set
//     * uses same auth params; body value provided as query param (simple).
//     * Example:
//     * /api/snmp/set?host=127.0.0.1&port=161&user=myUser&authPass=authPass&privPass=privPass&authProtocol=SHA&privProtocol=AES128&oid=1.3.6.1.2.1.1.5.0&value=hello
//     */
//    @PostMapping("/set")
//    public ResponseEntity<?> set(
//            @RequestParam String host,
//            @RequestParam(defaultValue = "161") int port,
//            @RequestParam String user,
//            @RequestParam String authPass,
//            @RequestParam String privPass,
//            @RequestParam(defaultValue = "SHA") String authProtocol,
//            @RequestParam(defaultValue = "AES128") String privProtocol,
//            @RequestParam String oid,
//            @RequestParam String value
//    ) {
//        try {
//            SnmpResponse resp = snmpService.set(host, port, user, authPass, privPass, authProtocol, privProtocol, oid, value);
//            return ResponseEntity.ok(resp);
//        } catch (IllegalArgumentException iae) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse("Invalid parameters", iae.getMessage()));
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorResponse("SNMP error", e.getMessage()));
//        }
//    }
}