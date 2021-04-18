package iam.customization.keycloak.authenticators;

import iam.customization.keycloak.model.EmailCredentialModel;
import iam.customization.keycloak.requireActions.EmailRequiredActionFactory;
import iam.customization.keycloak.requireActions.EmailRequiredAction;
import iam.customization.keycloak.services.EmailCredentialProvider;
import iam.customization.keycloak.services.EmailCredentialProviderFactory;
import iam.customization.keycloak.services.EmailCustomizationService;
import org.keycloak.authentication.*;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.email.EmailException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.TimeBasedOTP;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static iam.customization.keycloak.model.EmailCredentialModel.createSMSCredentialModel;
import static iam.customization.keycloak.requireActions.EmailRequiredAction.EMAIL_CONFIG_FORM;
import static iam.customization.keycloak.requireActions.EmailRequiredAction.EMAIL_SEND_ERROR;

public class EmailAuthenticator implements Authenticator, CredentialValidator<EmailCredentialProvider> {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        final EmailCredentialProvider provider = (EmailCredentialProvider) context.getSession()
                .getProvider(CredentialProvider.class, EmailCredentialProviderFactory.PROVIDER_ID);
        String secret = TimeBasedOTP.generateSecret(32);
        String generatedCode = provider.generateSMSCode(secret);

        final EmailCustomizationService emailCustomizationService = new EmailCustomizationService(context.getSession());
        try {
            emailCustomizationService.send2FAEmail(context.getUser(), generatedCode);
            createCredential(secret, context);
            Response challenge = context.form().createForm(EMAIL_CONFIG_FORM);
            context.challenge(challenge);
        } catch (EmailException e) {
            setErrorAndChallenge(context, EMAIL_CONFIG_FORM, EMAIL_SEND_ERROR);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        boolean validated = validateAnswer(context);
        if (!validated) {
            Response challenge = context.form()
                    .setError("badCode")
                    .createForm("email-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        context.success();
    }

    protected boolean validateAnswer(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String secret = formData.getFirst("emailCode");
        String credentialId = formData.getFirst("credentialId");
        if (credentialId == null || credentialId.isEmpty()) {
            credentialId = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser()).getId();
        }
        UserCredentialModel input = new UserCredentialModel(credentialId, getType(context.getSession()), secret);
        return getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), input);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction(EmailRequiredAction.PROVIDER_ID);
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return Collections.singletonList((EmailRequiredActionFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(RequiredActionProvider.class, EmailRequiredAction.PROVIDER_ID));
    }

    @Override
    public void close() {
    }

    @Override
    public EmailCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (EmailCredentialProvider) session.getProvider(CredentialProvider.class, EmailCredentialProviderFactory.PROVIDER_ID);
    }

    private void setErrorAndChallenge(AuthenticationFlowContext context,
                                      String form,
                                      String error) {
        Response challenge = context.form()
                .setError(error)
                .createForm(form);
        context.challenge(challenge);
    }

    private void createCredential(String secret, AuthenticationFlowContext context) {
        long expirationTime = Instant.now().plusSeconds(context.getRealm().getOTPPolicy().getPeriod()).toEpochMilli();
        final EmailCredentialModel smsCredentialModel = createSMSCredentialModel(expirationTime, secret);
        EmailCredentialProvider emailCredentialProvider = (EmailCredentialProvider) context.getSession()
                .getProvider(CredentialProvider.class, EmailCredentialProviderFactory.PROVIDER_ID);
        emailCredentialProvider.deleteAllCredentials(context.getRealm(), context.getUser());
        emailCredentialProvider.createCredential(context.getRealm(), context.getUser(), smsCredentialModel);
    }
}
