package com.example.keycloak.pin_grant;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class PinAuthenticator extends AbstractDirectGrantAuthenticator {


    public static final String ID = "custom_pin_authenticator";
    public static final String PROVIDER_ID = "direct-grant-validate-pin_custom";
    public static final String PIN_MAX_ATTEMPTS = "client.authc.pin.input.maxFailsNumber";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Map<String, List<String>> attributes = context.getUser().getAttributes();
        Integer numberOfFailedAttempts = Integer.valueOf(attributes.get("failedAttempts").get(0));
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Integer maxAttempts = Integer.valueOf(config.getConfig().get(PIN_MAX_ATTEMPTS));

        if (numberOfFailedAttempts >= maxAttempts) {
            context.getUser().setEnabled(false);
            attributes.remove("pin");
            attributes.put("pin", List.of("0"));

            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "max_attempts_exceeded", "Max attempts exceeded");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        System.out.println("i am inside custom pin authenticator");


        String pin = retrievePin(context);
/*        if (pin.endsWith("test")) {
            MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
            String sessionIdFromRequest = inputData.getFirst("authSessionId");
            System.out.println("authSessionFromRequest = " + sessionIdFromRequest);
            if (sessionIdFromRequest != null) {
                RootAuthenticationSessionModel rootAuthenticationSession = context.getSession().authenticationSessions().getRootAuthenticationSession(context.getRealm(), sessionIdFromRequest);
                if (rootAuthenticationSession != null) {
                    System.out.println("rootAuthenticationSession " + rootAuthenticationSession);
                }
            }
            String authSessionId = context.getAuthenticationSession().getParentSession().getId();
            System.out.println("authSessionId = " + authSessionId);
            context.getAuthenticationSession().setAuthNote("authSessionId", authSessionId);
            context.getAuthenticationSession().setAuthNote("generatedOTP", "012345");
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", authSessionId);
            context.forceChallenge(challengeResponse);
            return;
        }*/
        boolean valid = attributes.get("pin").get(0).equals(pin);
        if (!valid) {
            context.getUser().setSingleAttribute("failedAttempts", String.valueOf(numberOfFailedAttempts + 1));
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials custom_pin");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        //context.getAuthenticationSession().setAuthNote(AuthenticationManager.PASSWORD_VALIDATED, "true");
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public String getDisplayType() {
        return "Custom Pin Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "PIN";
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
    public String getHelpText() {
        return "My custom PIN authenticator";
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

    @Override
    public String getId() {
        return ID;
    }

    protected String retrievePin(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        return inputData.getFirst("pin");
    }

}
