package iam.customization.keycloak.requireActions;

import iam.customization.keycloak.model.EmailCredentialModel;
import iam.customization.keycloak.services.EmailCredentialProvider;
import iam.customization.keycloak.services.EmailCredentialProviderFactory;
import iam.customization.keycloak.services.EmailCustomizationService;
import org.keycloak.authentication.*;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.email.EmailException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.utils.TimeBasedOTP;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.time.Instant;

import static iam.customization.keycloak.model.EmailCredentialModel.createSMSCredentialModel;

public class EmailRequiredAction implements RequiredActionProvider, CredentialRegistrator {

    public static final String PROVIDER_ID = "email_2fa_config";
    public static final String EMAIL_CONFIG_ERROR_FORM = "email-validation-error.ftl";
    public static final String EMAIL_CONFIG_FORM = "email-validation.ftl";
    public static final String EMAIL_SEND_ERROR = "emailSendError";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        final EmailCredentialProvider provider = (EmailCredentialProvider) context.getSession()
                .getProvider(CredentialProvider.class, EmailCredentialProviderFactory.PROVIDER_ID);
        String secret = TimeBasedOTP.generateSecret(32);
        String code = provider.generateSMSCode(secret);
        final EmailCustomizationService emailCustomizationService = new EmailCustomizationService(context.getSession());
        try {
            emailCustomizationService.send2FAEmail(context.getUser(), code);
            createCredential(secret, context);
            Response challenge = context.form().createForm(EMAIL_CONFIG_FORM);
            context.challenge(challenge);
        } catch (EmailException e) {
            setErrorAndChallenge(context, EMAIL_CONFIG_ERROR_FORM, EMAIL_SEND_ERROR);
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        boolean validated = validateAnswer(context);
        if (!validated) {
            context.failure();
            return;
        }
        context.success();
    }


    protected boolean validateAnswer(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String secret = formData.getFirst("emailCode");
        String credentialId = formData.getFirst("credentialId");
        if (credentialId == null || credentialId.isEmpty()) {
            credentialId = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser()).getId();
        }
        UserCredentialModel input = new UserCredentialModel(credentialId, EmailCredentialModel.TYPE, secret);
        return getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), input);
    }


    private void setErrorAndChallenge(RequiredActionContext context, String form, String
            error) {
        Response challenge = context.form()
                .setError(error)
                .createForm(form);
        context.challenge(challenge);
    }

    private void createCredential(String secret, RequiredActionContext context) {
        long expirationTime = Instant.now().plusSeconds(context.getRealm().getOTPPolicy().getPeriod()).toEpochMilli();
        final EmailCredentialModel smsCredentialModel = createSMSCredentialModel(expirationTime, secret);
        EmailCredentialProvider emailCredentialProvider = (EmailCredentialProvider) context.getSession()
                .getProvider(CredentialProvider.class, EmailCredentialProviderFactory.PROVIDER_ID);
        emailCredentialProvider.deleteAllCredentials(context.getRealm(), context.getUser());
        emailCredentialProvider.createCredential(context.getRealm(), context.getUser(), smsCredentialModel);
    }

    @Override
    public void close() {

    }

    public EmailCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (EmailCredentialProvider) session.getProvider(CredentialProvider.class, EmailCredentialProviderFactory.PROVIDER_ID);
    }
}
