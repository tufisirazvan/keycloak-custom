package iam.customization.keycloak.authenticators;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class EmailAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "email-authenticator";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final EmailAuthenticator SINGLETON = new EmailAuthenticator();
    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Validates an OTP sent by email.";
    }

    @Override
    public String getDisplayType() {
        return "Email authentication";
    }

    @Override
    public String getReferenceCategory() {
        return "2fa-auth-code";
    }
    @Override
    public boolean isConfigurable() {
        return true;
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
