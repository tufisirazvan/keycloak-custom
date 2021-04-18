package iam.customization.keycloak.requireActions;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class EmailRequiredActionFactory implements RequiredActionFactory {

    private static final EmailRequiredAction SINGLETON = new EmailRequiredAction();

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return EmailRequiredAction.PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Email required action";
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
}
