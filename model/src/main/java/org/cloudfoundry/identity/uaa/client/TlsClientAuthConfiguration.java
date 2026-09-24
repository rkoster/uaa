package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import tools.jackson.core.type.TypeReference;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class TlsClientAuthConfiguration {

    public static final String TLS_CLIENT_AUTH_CA = "tls-client-auth-ca";
    public static final String TLS_CLIENT_AUTH_CLAIM_MAPPINGS = "tls-client-auth-claim-mappings";
    public static final String TLS_CLIENT_AUTH_SUB_TEMPLATE = "tls-client-auth-sub-template";
    public static final String TLS_CLIENT_AUTH_AUD_TEMPLATES = "tls-client-auth-aud-templates";
    public static final String TLS_CLIENT_AUTH_TRUSTED_PROXY_CA = "tls-client-auth-trusted-proxy-ca";
    public static final String TLS_CLIENT_AUTH_REQUIRED_CLAIMS = "tls-client-auth-required-claims";

    // UAA-owned token claims plus authentication context and certificate confirmation.
    // sub/aud may be configured through their dedicated templates, never through claim mappings.
    private static final Set<String> RESERVED_CLAIM_NAMES = Set.of(
            ClaimConstants.JTI, ClaimConstants.SUB, ClaimConstants.AUD, ClaimConstants.ISS,
            ClaimConstants.EXPIRY_IN_SECONDS, ClaimConstants.IAT, "nbf", ClaimConstants.ZONE_ID,
            ClaimConstants.SCOPE, ClaimConstants.GRANTED_SCOPES, ClaimConstants.AUTHORITIES,
            ClaimConstants.CLIENT_ID, ClaimConstants.CID, ClaimConstants.AZP, ClaimConstants.GRANT_TYPE,
            ClaimConstants.USER_ID, ClaimConstants.USER_NAME, ClaimConstants.ORIGIN, ClaimConstants.EMAIL,
            ClaimConstants.REVOCABLE, ClaimConstants.REVOCATION_SIGNATURE, ClaimConstants.PREVIOUS_LOGON_TIME,
            ClaimConstants.AMR, ClaimConstants.ACR, ClaimConstants.AUTH_TIME, ClaimConstants.CLIENT_AUTH_METHOD, "cnf");

    /** Tests the root claim, so dotted mappings cannot populate a reserved JWT object. */
    public static boolean isReservedClaimMapping(String claim) {
        int dot = claim.indexOf('.');
        return RESERVED_CLAIM_NAMES.contains(dot > 0 ? claim.substring(0, dot) : claim);
    }

    @JsonProperty(TLS_CLIENT_AUTH_CA)
    private String trustedCaPem;

    @JsonProperty(TLS_CLIENT_AUTH_CLAIM_MAPPINGS)
    private List<ClaimMapping> claimMappings;

    @JsonProperty(TLS_CLIENT_AUTH_SUB_TEMPLATE)
    private String subTemplate;

    @JsonProperty(TLS_CLIENT_AUTH_AUD_TEMPLATES)
    private List<String> audTemplates;

    @JsonProperty(TLS_CLIENT_AUTH_TRUSTED_PROXY_CA)
    private String trustedProxyCaPem;

    @JsonProperty(TLS_CLIENT_AUTH_REQUIRED_CLAIMS)
    private Map<String, String> requiredClaims;

    public TlsClientAuthConfiguration() {}

    public TlsClientAuthConfiguration(String trustedCaPem, List<ClaimMapping> claimMappings) {
        this.trustedCaPem = trustedCaPem;
        this.claimMappings = claimMappings;
    }

    public String getTrustedCaPem() { return trustedCaPem; }
    public void setTrustedCaPem(String trustedCaPem) { this.trustedCaPem = trustedCaPem; }

    public List<ClaimMapping> getClaimMappings() { return claimMappings; }
    public void setClaimMappings(List<ClaimMapping> claimMappings) { this.claimMappings = claimMappings; }

    public String getSubTemplate() { return subTemplate; }
    public void setSubTemplate(String subTemplate) { this.subTemplate = subTemplate; }

    public List<String> getAudTemplates() { return audTemplates; }
    public void setAudTemplates(List<String> audTemplates) { this.audTemplates = audTemplates; }

    public String getTrustedProxyCaPem() { return trustedProxyCaPem; }
    public void setTrustedProxyCaPem(String trustedProxyCaPem) { this.trustedProxyCaPem = trustedProxyCaPem; }

    public Map<String, String> getRequiredClaims() { return requiredClaims; }
    public void setRequiredClaims(Map<String, String> requiredClaims) { this.requiredClaims = requiredClaims; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TlsClientAuthConfiguration that)) return false;
        return Objects.equals(trustedCaPem, that.trustedCaPem) &&
               Objects.equals(claimMappings, that.claimMappings) &&
               Objects.equals(subTemplate, that.subTemplate) &&
               Objects.equals(audTemplates, that.audTemplates) &&
               Objects.equals(trustedProxyCaPem, that.trustedProxyCaPem) &&
               Objects.equals(requiredClaims, that.requiredClaims);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trustedCaPem, claimMappings, subTemplate, audTemplates, trustedProxyCaPem, requiredClaims);
    }

    public static boolean isConfigured(TlsClientAuthConfiguration config) {
        return config != null && config.getTrustedCaPem() != null && !config.getTrustedCaPem().isBlank();
    }

    /**
     * Reads the flat client metadata used by both authentication and token enhancement.
     * Structured properties accept native collections or JSON strings. Returns null when
     * no string CA is configured or JSON decoding fails; certificate and policy validation
     * remain the caller's responsibility.
     */
    public static TlsClientAuthConfiguration fromAdditionalInformation(Map<String, Object> info) {
        if (info == null || !(info.get(TLS_CLIENT_AUTH_CA) instanceof String pem)) {
            return null;
        }
        try {
            TlsClientAuthConfiguration config = new TlsClientAuthConfiguration(pem,
                    readStructuredValue(info.get(TLS_CLIENT_AUTH_CLAIM_MAPPINGS), List.class,
                            new TypeReference<List<ClaimMapping>>() {}));
            config.setSubTemplate(nonblankString(info.get(TLS_CLIENT_AUTH_SUB_TEMPLATE)));
            config.setAudTemplates(readStructuredValue(info.get(TLS_CLIENT_AUTH_AUD_TEMPLATES), List.class,
                    new TypeReference<List<String>>() {}));
            config.setTrustedProxyCaPem(nonblankString(info.get(TLS_CLIENT_AUTH_TRUSTED_PROXY_CA)));
            config.setRequiredClaims(readStructuredValue(info.get(TLS_CLIENT_AUTH_REQUIRED_CLAIMS), Map.class,
                    new TypeReference<Map<String, String>>() {}));
            return config;
        } catch (JsonUtils.JsonUtilException e) {
            return null;
        }
    }

    private static <T> T readStructuredValue(Object raw, Class<?> nativeType, TypeReference<T> type) {
        if (raw instanceof String json) {
            return JsonUtils.readValue(json, type);
        }
        return nativeType.isInstance(raw)
                ? JsonUtils.readValue(JsonUtils.writeValueAsString(raw), type) : null;
    }

    private static String nonblankString(Object raw) {
        return raw instanceof String value && !value.isBlank() ? value : null;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ClaimMapping {

        @JsonProperty("field")
        private String field;

        @JsonProperty("pattern")
        private String pattern;

        @JsonProperty("claim")
        private String claim;

        public ClaimMapping() {}

        public ClaimMapping(String field, String pattern, String claim) {
            this.field = field;
            this.pattern = pattern;
            this.claim = claim;
        }

        public String getField()   { return field; }
        public String getPattern() { return pattern; }
        public String getClaim()   { return claim; }

        public void setField(String field)     { this.field = field; }
        public void setPattern(String pattern) { this.pattern = pattern; }
        public void setClaim(String claim)     { this.claim = claim; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ClaimMapping that)) return false;
            return Objects.equals(field, that.field) &&
                   Objects.equals(pattern, that.pattern) &&
                   Objects.equals(claim, that.claim);
        }

        @Override
        public int hashCode() {
            return Objects.hash(field, pattern, claim);
        }
    }
}
