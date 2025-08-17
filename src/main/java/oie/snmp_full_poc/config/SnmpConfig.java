package oie.snmp_full_poc.config;

import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SnmpConfig {

    @Bean(destroyMethod = "close")
    public Snmp snmp() throws Exception {
        // transport
        TransportMapping<UdpAddress> transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        // message processing for v3
        MPv3 mpv3 = new MPv3();
        snmp.getMessageDispatcher().addMessageProcessingModel(mpv3);

        // add security protocols and models
        SecurityProtocols.getInstance().addDefaultProtocols();
        // optionally add specific auth/priv
        SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
        SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES128()); // Usually already in default protocols

        // local engine ID (let MPv3 create one)
        OctetString localEngineID = OctetString.fromByteArray(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
        SecurityModels.getInstance().addSecurityModel(usm);

        // start listening on transport
        transport.listen();

        return snmp;
    }

    /**
     * Helper to create a UsmUser that can be programmatically added to the USM.
     * Example usage is shown in service when building target users.
     */
    public static UsmUser createUsmUser(String username,
                                        OID authProtocolOid, String authPass,
                                        OID privProtocolOid, String privPass) {
        OctetString user = new OctetString(username);
        OctetString auth = authPass != null ? new OctetString(authPass) : null;
        OctetString priv = privPass != null ? new OctetString(privPass) : null;
        return new UsmUser(user, authProtocolOid, auth, privProtocolOid, priv);
    }
}

