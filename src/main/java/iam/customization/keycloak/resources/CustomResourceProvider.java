package iam.customization.keycloak.resources;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class CustomResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public CustomResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new CustomRestEndpoints(session);
    }

    @Override
    public void close() {
    }
}
