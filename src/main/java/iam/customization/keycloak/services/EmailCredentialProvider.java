package iam.customization.keycloak.services;

import iam.customization.keycloak.authenticators.EmailAuthenticatorFactory;
import iam.customization.keycloak.model.EmailCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.TimeBasedOTP;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class EmailCredentialProvider implements CredentialProvider<EmailCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(EmailCredentialProvider.class);

    protected KeycloakSession session;
    private TimeBasedOTP timeBasedOTP;

    public EmailCredentialProvider(KeycloakSession session) {
        this.session = session;
        RealmModel realmModel = session.getContext().getRealm();
        if (realmModel != null) {
            this.timeBasedOTP =
                    new TimeBasedOTP(realmModel.getOTPPolicy().getAlgorithm(),
                            realmModel.getOTPPolicy().getDigits(),
                            realmModel.getOTPPolicy().getPeriod(),
                            realmModel.getOTPPolicy().getLookAheadWindow());
        } else {
            this.timeBasedOTP = new TimeBasedOTP();
        }
    }

    private UserCredentialStore getCredentialStore() {
        return session.userCredentialManager();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;
        }
        if (!input.getType().equals(getType())) {
            return false;
        }
        String challengeResponse = input.getChallengeResponse();
        if (challengeResponse == null) {
            return false;
        }

        CredentialModel credentialModel = getCredentialStore().getStoredCredentialById(realm, user, input.getCredentialId());
        EmailCredentialModel emailCredential = getCredentialFromModel(credentialModel);
        return timeBasedOTP.validateTOTP(challengeResponse,
                emailCredential.getSMSSecretData().getSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) {
            return false;
        }
        return !getCredentialStore().getStoredCredentialsByType(realm, user, credentialType).isEmpty();
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, EmailCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return getCredentialStore().createCredential(realm, user, credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return getCredentialStore().removeStoredCredential(realm, user, credentialId);
    }

    public void deleteAllCredentials(RealmModel realm, UserModel user) {
        List<CredentialModel> storedCredentialsByType =
                getCredentialStore().getStoredCredentialsByType(realm, user, EmailCredentialModel.TYPE);
        storedCredentialsByType.forEach(cr -> getCredentialStore().removeStoredCredential(realm, user, cr.getId()));
    }

    @Override
    public EmailCredentialModel getCredentialFromModel(CredentialModel model) {
        return EmailCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName(EmailCredentialProviderFactory.PROVIDER_DISPLAY_NAME)
                .helpText(EmailCredentialProviderFactory.PROVIDER_HELP_TEXT)
                .createAction(EmailAuthenticatorFactory.PROVIDER_ID)
                .removeable(false)
                .build(session);
    }

    @Override
    public String getType() {
        return EmailCredentialModel.TYPE;
    }

    public String generateSMSCode(String secret) {
        return timeBasedOTP.generateTOTP(secret);
    }
}
