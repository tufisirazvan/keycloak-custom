package iam.customization.keycloak.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EmailSecretData {

    private final String secret;

    @JsonCreator
    public EmailSecretData(@JsonProperty("secret") String secret) {
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }
}
