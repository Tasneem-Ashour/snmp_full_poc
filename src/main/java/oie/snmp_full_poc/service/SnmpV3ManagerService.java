package oie.snmp_full_poc.service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
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
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SnmpV3ManagerService {

    private Snmp snmp;
    private  final ConcurrentHashMap<String, Boolean> addedUsers = new ConcurrentHashMap<>();

    @PostConstruct
    public void start() throws IOException {
        System.setProperty("org.snmp4j.log.LogFactory", "org.snmp4j.log.JavaLogFactory");
        LogFactory.setLogFactory(new JavaLogFactory());

        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        MessageDispatcherImpl dispatcher = new MessageDispatcherImpl();

        dispatcher.addMessageProcessingModel(new MPv3());
        snmp = new Snmp(dispatcher,transport);

        SecurityProtocols.getInstance().addDefaultProtocols();
        SecurityModels.getInstance().addSecurityModel(
                new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()),0)
        );
        transport.listen();
        System.out.println("✅ SNMPv3 Manager started and listening");


    }

    @PreDestroy
    public void stop() throws IOException {
        if (snmp != null) {
        snmp.close();
        System.out.println("SNMPv3 Manager stopped");
    }
    }


    private void ensureUser(String username, String authPass, String privPass) {
        if (addedUsers.putIfAbsent(username, Boolean.TRUE) == null) {
            // choose strong algorithms in real systems: SHA-256, AES-128/256 etc.
            UsmUser user = new UsmUser(
                    new OctetString(username),
                    AuthSHA.ID,                 // auth protocol (example: SHA)
                    new OctetString(authPass),
                    PrivAES128.ID,              // priv protocol (example: AES128)
                    new OctetString(privPass)
            );
            snmp.getUSM().addUser(user.getSecurityName(), user);

            System.out.println("👤 Added SNMPv3 user: " + username);

        }
    }

    public String getAsString(String host, int port, String username, String authPass, String privPass, String oid) throws IOException {
        ensureUser(username, authPass, privPass);

        // Discover engine ID before sending request
        System.out.println("🔍 Discovering engine ID for " + host + ":" + port);
        snmp.discoverAuthoritativeEngineID(GenericAddress.parse("udp:" + host + "/" + port), 5000);

        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        pdu.add(new VariableBinding(new OID(oid)));

        UserTarget target = new UserTarget();
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(2);
        target.setTimeout(5000); // Increased timeout
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString(username));

        System.out.println("📡 Sending SNMP GET for OID " + oid);
        ResponseEvent resp = snmp.send(pdu, target);

        if (resp == null || resp.getResponse() == null) {
            throw new IOException("SNMP request timed out or returned no response");
        }

        VariableBinding vb = resp.getResponse().get(0);
        return vb.getVariable().toString();
    }

    public void setString(String host, int port, String username, String authPass, String privPass, String oid, String value) throws IOException {
        ensureUser(username, authPass, privPass);

        // Discover engine ID before sending request
        System.out.println("🔍 Discovering engine ID for " + host + ":" + port);
        snmp.discoverAuthoritativeEngineID(GenericAddress.parse("udp:" + host + "/" + port), 5000);

        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.SET);
        pdu.add(new VariableBinding(new OID(oid), new OctetString(value)));

        UserTarget target = new UserTarget();
        target.setAddress(GenericAddress.parse("udp:" + host + "/" + port));
        target.setRetries(2);
        target.setTimeout(5000);
        target.setVersion(SnmpConstants.version3);
//        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
        target.setSecurityName(new OctetString(username));

        System.out.println("📡 Sending SNMP SET for OID " + oid + " with value: " + value);
        ResponseEvent resp = snmp.send(pdu, target);

        if (resp == null || resp.getResponse() == null) {
            throw new IOException("SNMP SET timed out or returned no response");
        }
        PDU responsePdu = resp.getResponse();
        if (responsePdu.getErrorStatus() != PDU.noError) {
            throw new IOException("SNMP SET error: " + responsePdu.getErrorStatusText());
        }
    }
}


