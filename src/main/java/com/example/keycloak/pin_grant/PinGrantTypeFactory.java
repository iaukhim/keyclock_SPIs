package com.example.keycloak.pin_grant;

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;
import org.keycloak.protocol.oidc.grants.ResourceOwnerPasswordCredentialsGrantType;

public class PinGrantTypeFactory implements OAuth2GrantTypeFactory {

    @Override
    public String getId() {
        return "CUSTOM_PIN";
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new PinGrantType();
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
