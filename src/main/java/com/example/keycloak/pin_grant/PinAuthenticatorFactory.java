package com.example.keycloak.pin_grant;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

import static com.example.keycloak.pin_grant.PinAuthenticator.PIN_MAX_ATTEMPTS;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class PinAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "custom_pin_authenticator";

    private static final Authenticator AUTHENTICATOR_INSTANCE = new PinAuthenticator();

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return AUTHENTICATOR_INSTANCE;
    }

    @Override
    public String getDisplayType() {
        return "Custom Pin Authenticator";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] { AuthenticationExecutionModel.Requirement.REQUIRED };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "My custom PIN authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty maxAttempts = new ProviderConfigProperty();
        maxAttempts.setType(STRING_TYPE);
        maxAttempts.setName(PIN_MAX_ATTEMPTS);
        maxAttempts.setLabel("Max PIN attempts");
        maxAttempts.setHelpText("Maximum allowed PIN attempts before lockout (empty for unlimited)");
        maxAttempts.setDefaultValue("");

        return List.of(maxAttempts);
    }
}
