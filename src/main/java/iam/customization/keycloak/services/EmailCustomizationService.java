package iam.customization.keycloak.services;


import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.theme.Theme;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class EmailCustomizationService {

    private static final Logger logger = Logger.getLogger(EmailCustomizationService.class);

    private final KeycloakSession session;

    public EmailCustomizationService(KeycloakSession session) {
        this.session = session;
    }

    public void send2FAEmail(UserModel user, String code) throws EmailException {
        RealmModel realm = session.getContext().getRealm();
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("name", user.getFirstName());
        attributes.put("username", user.getUsername());
        attributes.put("code",code);

        String subjectName = "secondFactorEmailSubject";
        String templateName = "secondFactor.ftl";

        attributes.put("resourceUrl", getResourcesPath(session));
        session
                .getProvider(EmailTemplateProvider.class)
                .setRealm(realm)
                .setUser(user)
                .send(subjectName, templateName, attributes);
    }

    public static String getResourcesPath(KeycloakSession session) {
        URI uri = Urls.themeRoot(session.getContext().getUri().getBaseUri());
        return uri.toString() + "/" + getTheme(session).getType().toString().toLowerCase() + "/" + getTheme(session).getName();
    }

    private static Theme getTheme(KeycloakSession session) {
        try {
            return session.theme().getTheme(Theme.Type.EMAIL);
        } catch (IOException e) {
            logger.error("Failed to get email resources", e);
            throw new IllegalStateException("Failed to get email resources {} : ");
        }
    }
}
