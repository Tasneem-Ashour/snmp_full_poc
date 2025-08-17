package oie.snmp_full_poc.service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import oie.snmp_full_poc.dto.SnmpResponse;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.JavaLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SnmpV3ManagerService {

    private Snmp snmp;
    // keep track of added user keys: host:port:username:authAlg:privAlg
    private final Map<String, Boolean> addedUsers = new ConcurrentHashMap<>();

//    @PostConstruct
//    public void start() throws IOException {
//        // Logging factory
//        System.setProperty("org.snmp4j.log.LogFactory", JavaLogFactory.class.getName());
//        LogFactory.setLogFactory(new JavaLogFactory());
//
//        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
//        MessageDispatcherImpl dispatcher = new MessageDispatcherImpl();
//        dispatcher.addMessageProcessingModel(new MPv3());
//
//        snmp = new Snmp(dispatcher, transport);
//
//        SecurityProtocols.getInstance().addDefaultProtocols();
//        // add USM with a local engine ID
//        SecurityModels.getInstance().addSecurityModel(
//                new USM(SecurityProtocols.getInstance(),
//                        new OctetString(MPv3.createLocalEngineID()), 0)
//        );
//
//        transport.listen();
//        System.out.println("✅ SNMPv3 Manager started");
//    }

    @PreDestroy
    public void stop() throws IOException {
        if (snmp != null) {
            snmp.close();
            System.out.println("🛑 SNMPv3 Manager stopped");
        }
    }

    /**
     * Map auth protocol name to OID constant.
     */
    private OID mapAuthProtocol(String authProtocol) {
        if (authProtocol == null) return null;
        switch (authProtocol.toUpperCase(Locale.ROOT)) {
            case "MD5":   return AuthMD5.ID;
            case "SHA":   return AuthSHA.ID;
            case "SHA256": return AuthHMAC192SHA256.ID; // if available
            case "SHA384": return AuthHMAC256SHA384.ID;
            case "SHA512": return AuthHMAC384SHA512.ID;
            default: throw new IllegalArgumentException("Unsupported authProtocol: " + authProtocol);
        }
    }

    /**
     * Map priv protocol name to OID constant.
     */
    private OID mapPrivProtocol(String privProtocol) {
        if (privProtocol == null) return null;
        switch (privProtocol.toUpperCase(Locale.ROOT)) {
            case "DES":    return PrivDES.ID;
            case "AES":    // allow AES as AES128
            case "AES128": return PrivAES128.ID;
            case "AES192": return PrivAES192.ID;
            case "AES256": return PrivAES256.ID;
            default: throw new IllegalArgumentException("Unsupported privProtocol: " + privProtocol);
        }
    }

    /**
     * Discover engine ID and register the user in USM bound to that engine ID.
     * Returns the discovered engineId.
     */
    private OctetString discoverAndRegisterUser(String host, int port,
                                                String username, String authPass, String privPass,
                                                String authProtocol, String privProtocol) throws IOException {

        String key = host + ":" + port + ":" + username + ":" + authProtocol + ":" + privProtocol;
        // discover engine ID
        System.out.println("🔍 Discovering engine ID for " + host + ":" + port);
        byte[] engineRaw = snmp.discoverAuthoritativeEngineID(GenericAddress.parse("udp:" + host + "/" + port), 5000);
        if (engineRaw == null) {
            throw new IOException("Failed to discover authoritative engine ID from " + host + ":" + port);
        }
        OctetString engineId = OctetString.fromByteArray(engineRaw);
        System.out.println("✅ Discovered engine ID: " + engineId);

        // only add user once per host:port:username:alg combo
        if (addedUsers.putIfAbsent(key, Boolean.TRUE) == null) {
            // validate algorithm names
            OID authOid = mapAuthProtocol(authProtocol);
            OID privOid = mapPrivProtocol(privProtocol);

            if (authPass == null || authPass.isEmpty()) {
                throw new IllegalArgumentException("authPass must be provided for authProtocols that require authentication");
            }
            if (privPass == null || privPass.isEmpty()) {
                throw new IllegalArgumentException("privPass must be provided for privProtocols that require privacy");
            }

            // create UsmUser bound to the discovered engineId
            UsmUser user = new UsmUser(new OctetString(username),
                    authOid, new OctetString(authPass),
                    privOid, new OctetString(privPass));

            // Important: add user bound to engineId
            snmp.getUSM().addUser(new OctetString(username), engineId, user);
            System.out.println("👤 Registered SNMPv3 user '" + username + "' for engine " + engineId);
        }

        return OctetString.fromByteArray(engineRaw);
    }

    /**
     * SNMP GET returning SnmpResponse DTO
     */
    public SnmpResponse get(String host, int port, String username,
                            String authPass, String privPass,
                            String authProtocol, String privProtocol,
                            String oid) throws IOException {

        OctetString engineId = discoverAndRegisterUser(host, port, username, authPass, privPass, authProtocol, privProtocol);

        // build PDU
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        pdu.add(new VariableBinding(new OID(oid)));

        // target
        UserTarget target = new UserTarget();
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(2);
        target.setTimeout(5000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString(username));
        // leave authoritative engine ID unset on target; USM user entry binds engineId

        ResponseEvent event = snmp.send(pdu, target);
        if (event == null || event.getResponse() == null) {
            throw new IOException("SNMP request timed out or returned no response");
        }
        PDU responsePdu = event.getResponse();
        if (responsePdu.getErrorStatus() != PDU.noError) {
            throw new IOException("SNMP error: " + responsePdu.getErrorStatusText());
        }

        String value = responsePdu.get(0).getVariable().toString();
        return new SnmpResponse(engineId.toString(), oid, value);
    }

    /**
     * SNMP SET returning SnmpResponse DTO
     * (Assumes OID expects an OctetString. For other types you'd need type detection/param)
     */
    public SnmpResponse set(String host, int port, String username,
                            String authPass, String privPass,
                            String authProtocol, String privProtocol,
                            String oid, String value) throws IOException {

        OctetString engineId = discoverAndRegisterUser(host, port, username, authPass, privPass, authProtocol, privProtocol);

        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.SET);
        pdu.add(new VariableBinding(new OID(oid), new OctetString(value)));

        UserTarget target = new UserTarget();
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(2);
        target.setTimeout(5000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString(username));

        ResponseEvent event = snmp.send(pdu, target);
        if (event == null || event.getResponse() == null) {
            throw new IOException("SNMP SET timed out or returned no response");
        }
        PDU responsePdu = event.getResponse();
        if (responsePdu.getErrorStatus() != PDU.noError) {
            throw new IOException("SNMP SET error: " + responsePdu.getErrorStatusText());
        }

        String returned = responsePdu.get(0).getVariable().toString();
        return new SnmpResponse(engineId.toString(), oid, returned);
    }
}