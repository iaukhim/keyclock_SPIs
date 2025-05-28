package com.example.keycloak;

import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserCredentialModel;

import java.util.List;
import java.util.stream.Stream;

public class CustomCredentialManager implements SubjectCredentialManager {

    @Override
    public boolean isValid(List<CredentialInput> inputs) {
        System.out.println("isValid, " + inputs);
        return true;
    }

    @Override
    public boolean updateCredential(CredentialInput input) {
        return false;
    }

    @Override
    public void updateStoredCredential(CredentialModel cred) {

    }

    @Override
    public CredentialModel createStoredCredential(CredentialModel cred) {
        return null;
    }

    @Override
    public boolean removeStoredCredentialById(String id) {
        return false;
    }

    @Override
    public CredentialModel getStoredCredentialById(String id) {
        return null;
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsStream() {
        return Stream.empty();
    }

    @Override
    public Stream<CredentialModel> getStoredCredentialsByTypeStream(String type) {
        return Stream.empty();
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(String name, String type) {
        return null;
    }

    @Override
    public boolean moveStoredCredentialTo(String id, String newPreviousCredentialId) {
        return false;
    }

    @Override
    public void updateCredentialLabel(String credentialId, String credentialLabel) {

    }

    @Override
    public void disableCredentialType(String credentialType) {

    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream() {
        return Stream.empty();
    }

    @Override
    public boolean isConfiguredFor(String type) {
        return false;
    }

    @Override
    public boolean isConfiguredLocally(String type) {
        return false;
    }

    @Override
    public Stream<String> getConfiguredUserStorageCredentialTypesStream() {
        return Stream.empty();
    }

    @Override
    public CredentialModel createCredentialThroughProvider(CredentialModel model) {
        return null;
    }
}
