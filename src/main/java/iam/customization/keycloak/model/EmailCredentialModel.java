package iam.customization.keycloak.model;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class EmailCredentialModel extends CredentialModel {

    public static final String TYPE = "EMAIL";

    private final EmailCredentialData credentialData;
    private final EmailSecretData secretData;

    private EmailCredentialModel(EmailCredentialData credentialData,
                                 EmailSecretData secretData) {
        this.credentialData = credentialData;
        this.secretData = secretData;
    }

    private EmailCredentialModel(Long expirationDate, String secret) {
        credentialData = new EmailCredentialData(expirationDate);
        secretData = new EmailSecretData(secret);
    }

    public static EmailCredentialModel createSMSCredentialModel(Long expirationDate, String answer) {
        EmailCredentialModel credentialModel = new EmailCredentialModel(expirationDate, answer);
        credentialModel.fillCredentialModelFields();
        return credentialModel;
    }

    public static EmailCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            EmailCredentialData credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(), EmailCredentialData.class);
            EmailSecretData secretData = JsonSerialization.readValue(credentialModel.getSecretData(), EmailSecretData.class);

            EmailCredentialModel smsCredentialModel = new EmailCredentialModel(credentialData, secretData);
            smsCredentialModel.setUserLabel(credentialModel.getUserLabel());
            smsCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
            smsCredentialModel.setType(TYPE);
            smsCredentialModel.setId(credentialModel.getId());
            smsCredentialModel.setSecretData(credentialModel.getSecretData());
            smsCredentialModel.setCredentialData(credentialModel.getCredentialData());
            return smsCredentialModel;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public EmailCredentialData getSMSCredentialData() {
        return credentialData;
    }

    public EmailSecretData getSMSSecretData() {
        return secretData;
    }

    private void fillCredentialModelFields() {
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData(JsonSerialization.writeValueAsString(secretData));
            setType(TYPE);
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
