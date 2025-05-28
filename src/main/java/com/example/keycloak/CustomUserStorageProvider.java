package com.example.keycloak;

import com.example.keycloak.user.MyCustomUser;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;



public class CustomUserStorageProvider implements
        UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator {

    private final KeycloakSession ksession;
    private final ComponentModel model;
    private final Logger logger;

    public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
        this.logger = Logger.getLogger(CustomUserStorageProvider.class);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        System.out.println("At supportsCredentialType method. Got credentialType parameter = " + credentialType);
        //logger.log(Logger.Level.WARN, "At supportsCredentialType method. Got credentialType parameter = " + credentialType);
        return  credentialType.equals("password");
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        System.out.println(String.format("At isConfiguredFor method. Got parameters " +
                "realm = %s, " +
                "user = %s, " +
                "credentialType = %s ", realm.toString(), user.getUsername(), credentialType));
        /*logger.log(Logger.Level.WARN, String.format("At isConfiguredFor method. Got parameters " +
                "realm = %s, " +
                "user = %s, " +
                "credentialType = %s ", realm.toString(), user.getUsername(), credentialType));*/
        return  credentialType.equals("password");
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        System.out.println(String.format("At isValid method. Got parameters " +
                "realm = %s, " +
                "user = %s, " +
                "credentialInput = %s ", realm.toString(), user.getUsername(), credentialInput));

        UserCredentialModel cred = (UserCredentialModel) credentialInput;

        String rawPassword = cred.getChallengeResponse();
        System.out.println("rawPassword = " + rawPassword);

        AuthenticationSessionModel authSession = ksession.getContext().getAuthenticationSession();
        System.out.println("authSession != null" + authSession != null);
        String instituteId = authSession.getClientNote("institute_id");
        System.out.println(authSession.getClientNotes());
        System.out.println("Institute ID: " + instituteId); // Should show "5"
        /*logger.log(Logger.Level.WARN, String.format("At isValid method. Got parameters " +
                "realm = %s, " +
                "user = %s, " +
                "credentialInput = %s ", realm.toString(), user.getUsername(), credentialInput));*/
        return true;
    }

    @Override
    public void close() {

    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        System.out.println("getUserById, realm = " + realm  + " id = " + id);
        return null;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        System.out.println("getUserByUsername, realm = " + realm  + " username = " + username);
        return new MyCustomUser(ksession, realm, model, username);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        System.out.println("getUserByEmail, realm = " + realm  + " email = " + email);
        return null;
    }

    // ... implementation methods for each supported capability
}

