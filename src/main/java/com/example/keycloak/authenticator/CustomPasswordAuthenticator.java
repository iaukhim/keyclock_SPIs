package com.example.keycloak.authenticator;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.directgrant.ValidatePassword;

public class CustomPasswordAuthenticator extends ValidatePassword {

    public static final String CUSTOM_HEADER_CLIENT_INFO_PREFIX = "X-clientInfo-";

    public CustomPasswordAuthenticator() {
        super();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Custom password authenticator");

        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();

        System.out.println("headers " + headers.getRequestHeaders());
        // Collect relevant headers in session notes
        headers.getRequestHeaders().entrySet().stream()
                .filter(entry -> entry.getKey() != null && entry.getKey().startsWith(CUSTOM_HEADER_CLIENT_INFO_PREFIX))
                .filter(entry -> !entry.getValue().isEmpty())
                .forEach(entry -> {
                    String firstValue = entry.getValue().get(0);
                    if (firstValue != null) {
                        context.getAuthenticationSession()
                                .setUserSessionNote(entry.getKey(), firstValue);
                    }
                });
        super.authenticate(context);
    }


}
