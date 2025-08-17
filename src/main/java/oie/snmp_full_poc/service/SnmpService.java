package oie.snmp_full_poc.service;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TreeEvent;
import org.snmp4j.util.TreeUtils;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SnmpService {

    private final Snmp snmp;

    public SnmpService(Snmp snmp) {
        this.snmp = snmp;
    }

    private void addUserToUSM(UsmUser user) {
        // programmatically add a user to local USM so outgoing SNMPv3 calls can reference it
        try {
            USM usm = (USM) SecurityModels.getInstance().getSecurityModel(new Integer32 (SecurityModel.SECURITY_MODEL_USM));
            usm.addUser(user.getSecurityName(), user);
        } catch (Exception e) {
            // ignore if already added or handle logging
        }
    }

    public String get(String host, int port, String username,
                      OID authProtocol, String authPass,
                      OID privProtocol, String privPass,
                      String oid) throws Exception {

        // add user to local USM (optional, helpful for authoritative engine discovery)
        UsmUser user = new UsmUser(new OctetString(username),
                authProtocol, new OctetString(authPass),
                privProtocol, new OctetString(privPass));
        addUserToUSM(user);

        Address targetAddress = new UdpAddress(host + "/" + port);
        UserTarget target = new UserTarget();
        target.setAddress(targetAddress);
        // choose the right security level
        if (authPass != null && privPass != null) {
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        } else if (authPass != null) {
            target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
        } else {
            target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
        }
        target.setSecurityName(new OctetString(username));
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version3);

        // create scoped PDU
        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.GET);
        pdu.add(new VariableBinding(new OID(oid)));

        ResponseEvent resp = snmp.send(pdu, target);
        if (resp == null || resp.getResponse() == null) {
            throw new RuntimeException("Timeout / No response from target");
        }
        PDU responsePDU = resp.getResponse();
        if (responsePDU.getErrorStatus() != PDU.noError) {
            throw new RuntimeException("SNMP Error: " + responsePDU.getErrorStatusText());
        }
        VariableBinding vb = responsePDU.get(0);
        return vb.toValueString();
    }

    public List<String> walk(String host, int port, String username,
                             OID authProtocol, String authPass,
                             OID privProtocol, String privPass,
                             String baseOid) throws Exception {

        UsmUser user = new UsmUser(new OctetString(username),
                authProtocol, new OctetString(authPass),
                privProtocol, new OctetString(privPass));
        addUserToUSM(user);

        Address targetAddress = new UdpAddress(host + "/" + port);
        UserTarget target = new UserTarget();
        target.setAddress(targetAddress);
        if (authPass != null && privPass != null) {
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        } else if (authPass != null) {
            target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
        } else {
            target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
        }
        target.setSecurityName(new OctetString(username));
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version3);

        TreeUtils treeUtils = new TreeUtils(snmp, new DefaultPDUFactory());
        List<TreeEvent> events = treeUtils.getSubtree(target, new OID(baseOid));

        List<String> results = new ArrayList<>();
        if (events == null || events.isEmpty()) {
            return results;
        }
        for (TreeEvent event : events) {
            if (event == null) continue;
            if (event.isError()) continue;
            VariableBinding[] varBindings = event.getVariableBindings();
            if (varBindings == null) continue;
            for (VariableBinding vb : varBindings) {
                results.add(vb.getOid() + " = " + vb.getVariable());
            }
        }
        return results;
    }

    // For brevity, SET is omitted — it follows the same pattern: create ScopedPDU with PDU.SET and VariableBindings.
}

