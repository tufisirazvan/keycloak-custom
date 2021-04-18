package iam.customization.keycloak.services;

import iam.customization.keycloak.model.EmailCredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class EmailCredentialProviderFactory implements CredentialProviderFactory<EmailCredentialProvider> {
    public static final String PROVIDER_ID = "email-credential";
    public static final String PROVIDER_DISPLAY_NAME = "email-display-name";
    public static final String PROVIDER_HELP_TEXT = "email-help-text";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public CredentialProvider<EmailCredentialModel> create(KeycloakSession session) {
        return new EmailCredentialProvider(session);
    }
}
