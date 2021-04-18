package iam.customization.keycloak.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EmailCredentialData {

    private final Long expirationDate;

    @JsonCreator
    public EmailCredentialData(@JsonProperty("expirationDate") Long expirationDate) {
        this.expirationDate = expirationDate;
    }

    public Long getExpirationDate() {
        return expirationDate;
    }
}
