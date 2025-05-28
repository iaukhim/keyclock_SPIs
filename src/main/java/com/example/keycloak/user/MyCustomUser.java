package com.example.keycloak.user;

import com.example.keycloak.CustomCredentialManager;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.storage.adapter.AbstractUserAdapter;

public class MyCustomUser extends AbstractUserAdapter {

    private final String username;

    public MyCustomUser(KeycloakSession session, RealmModel realm, ComponentModel storageProviderModel,
                        String username) {
        super(session, realm, storageProviderModel);
        this.username = username;
    }

    @Override
    public String getUsername() {
        return new String(username);
    }

    @Override
    public SubjectCredentialManager credentialManager() {
        return new CustomCredentialManager();
    }
}
