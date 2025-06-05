package com.example.keycloak.user;

import com.example.keycloak.CustomCredentialManager;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.storage.adapter.AbstractUserAdapter;

import java.util.List;
import java.util.Map;

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

    @Override
    public Map<String, List<String>> getAttributes() {
        System.out.println("At getAttributes method");
        Map<String, List<String>> attributes = super.getAttributes();
        attributes.put("external_id", List.of("someExternalId"));
        attributes.put("username", List.of("externalUserUsername"));
        return attributes;
    }

    @Override
    public void removeRequiredAction(String action) {
        System.out.println("at removeRequiredAction. Got action = " + action);
    }


}
