package iam.customization.keycloak.resources;

import org.jboss.logging.Logger;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.List;
import java.util.stream.Collectors;

public class CustomRestEndpoints {

    private static final Logger logger = Logger.getLogger(CustomRestEndpoints.class);

    private final KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;

    public CustomRestEndpoints(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager().authenticateBearerToken(session, session.getContext().getRealm());
    }


    @GET
    @Path("attribute-search")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<UserRepresentation> get(
            @QueryParam("attributeName") String attributeName,
            @QueryParam("attributeValue") String attributeValue) {
        checkCanQueryUsers();
        final RealmModel realm = session.getContext().getRealm();
        final List<UserModel> users = session.users()
                .searchForUserByUserAttribute(attributeName, attributeValue, realm);

        return users.stream().map(e -> ModelToRepresentation.toRepresentation(session, realm, e))
                .collect(Collectors.toList());
    }


    private void checkCanQueryUsers() {
        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        }
    }
}
