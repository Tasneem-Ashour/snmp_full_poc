package oie.snmp_full_poc.dto;

public class SnmpResponse {
    private String engineId;
    private String oid;
    private String value;

    public SnmpResponse() {}

    public SnmpResponse(String engineId, String oid, String value) {
        this.engineId = engineId;
        this.oid = oid;
        this.value = value;
    }

    public String getEngineId() { return engineId; }
    public void setEngineId(String engineId) { this.engineId = engineId; }

    public String getOid() { return oid; }
    public void setOid(String oid) { this.oid = oid; }

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
}