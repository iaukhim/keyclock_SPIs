package com.example.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.UserCredentialManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.user.UserLookupProvider;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.example.keycloak.authenticator.CustomPasswordAuthenticator.CUSTOM_HEADER_CLIENT_INFO_PREFIX;
import static org.keycloak.models.UserModel.RequiredAction.VERIFY_PROFILE;


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
    public void close() {

    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        System.out.println("getUserById, realm = " + realm  + " id = " + id);
        StorageId storageId = new StorageId(id);
        if (storageId.getProviderId() == null
                || !storageId.getProviderId().equals(model.getId())) {
            System.out.println("not this SPI's user.");
            return null;
        }

        return getUserByUsername(realm, storageId.getExternalId());
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        System.out.println("getUserByUsername, realm = " + realm  + " username = " + username);

        // 1. First check your external user federation
        // Create HTTP client
        HttpClient client = HttpClient.newHttpClient();

        String requestBody = String.format(
                "{\"username\":\"%s\"," +
                        "\"realmName\":\"%s\"}",
                username,
                realm.getName()
        );

        // Create HTTP request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:7099/authentication-service/api/v1/identification/external/identify"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(60))
                .build();

        // Send request and get response
        HttpResponse<String> response = null;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) {
                System.out.println("not external user so SPI returns null");
                return null;
            }

            String externalId = response.body();
            return createAdapter(realm, username, externalId);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return null;
    }

    // ... implementation methods for each supported capability


    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return credentialType.equals(PasswordCredentialModel.TYPE);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(PasswordCredentialModel.TYPE);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        System.out.println("isValid method ");

        AuthenticationSessionModel authSession = ksession.getContext().getAuthenticationSession();

        // Get all stored clientInfo parameters
        Map<String, String> clientInfoParameters = authSession.getUserSessionNotes().entrySet().stream()
                .filter(entry -> entry.getKey().startsWith(CUSTOM_HEADER_CLIENT_INFO_PREFIX))
                .collect(Collectors.toMap(
                        entry -> entry.getKey().substring(CUSTOM_HEADER_CLIENT_INFO_PREFIX.length()), // remove prefix
                        Map.Entry::getValue
                ));

        System.out.println(String.format("headers gotten from sessionNotes %s", clientInfoParameters));

        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) return false;

        UserCredentialModel cred = (UserCredentialModel)input;
        try {
            HttpResponse httpResponse = authenticateExternally(realm, user, input, clientInfoParameters);
            return httpResponse.statusCode() == 201;
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }


    protected UserModel createAdapter(RealmModel realm, String username, String externalId) {
        return new AbstractUserAdapter(ksession, realm, model) {

            @Override
            public String getId() {
                return "f:" + model.getId() + ":" + getUsername();
            }

            @Override
            public String getUsername() {
                return username;
            }

            @Override
            public SubjectCredentialManager credentialManager() {
                return new UserCredentialManager(session, realm, this);
            }

            @Override
            public Stream<String> getRequiredActionsStream() {
                return Stream.empty();
            }

            @Override
            public void removeRequiredAction(String action) {
                // Silently ignore VERIFY_PROFILE (or other actions)
                if (!"VERIFY_PROFILE".equals(action)) {
                    throw new ReadOnlyException("User is read-only");
                }
            }

            @Override
            public void addRequiredAction(String action) {
                if (!"VERIFY_PROFILE".equals(action)) {
                    throw new ReadOnlyException("User is read-only");
                }
            }

            @Override
            public void addRequiredAction(RequiredAction action) {
                if (!VERIFY_PROFILE.equals(action)) {
                    throw new ReadOnlyException("User is read-only");
                }
            }

            @Override
            public Map<String, List<String>> getAttributes() {
                Map<String, List<String>> attributes = super.getAttributes();
                attributes.put("external_id", List.of(externalId));
                return attributes;
            }

            @Override
            public String getFirstAttribute(String name) {
                if (name.equals(UserModel.USERNAME)) {
                    return getUsername();
                }

                List<String> requestedAttributeValues = getAttributes().get(name);

                return Optional.ofNullable(requestedAttributeValues)
                        .map(Collection::iterator)
                        .map(Iterator::next)
                        .orElse(null);
            }

            @Override
            public List<String> getAttribute(String name) {
                if (name.equals(UserModel.USERNAME)) {
                    return List.of(getUsername());
                }

                return Optional.ofNullable(getAttributes().get(name))
                        .orElse(Collections.emptyList());
            }
        };
    }

    private HttpResponse authenticateExternally(RealmModel realm, UserModel user, CredentialInput input,
                                                Map<String, String> clientInfoParameters) throws IOException, InterruptedException {
        UserCredentialModel cred = (UserCredentialModel) input;
        String password = cred.getValue();
        String username = user.getUsername();
        String realmName = realm.getName();

        // Create HTTP client
        HttpClient client = HttpClient.newHttpClient();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode requestBody = mapper.createObjectNode();
        requestBody.put("username", username);
        requestBody.put("password", password);
        requestBody.put("realm", realmName);

// Helper function to handle empty strings
        BiConsumer<String, String> addField = (field, value) -> {
            if (value != null && value.isEmpty()) {
                requestBody.putNull(field);
            } else {
                requestBody.put(field, value);
            }
        };

        addField.accept("locale", clientInfoParameters.get("locale"));
        addField.accept("customerType", clientInfoParameters.get("customerType"));
        addField.accept("customerSubType", clientInfoParameters.get("customerSubType"));
        addField.accept("serviceType", clientInfoParameters.get("serviceType"));
        addField.accept("channel", clientInfoParameters.get("channel"));
        addField.accept("macAddress", clientInfoParameters.get("macAddress"));
        addField.accept("imei", clientInfoParameters.get("imei"));
        addField.accept("imsi", clientInfoParameters.get("imsi"));
        addField.accept("deviceIp", clientInfoParameters.get("deviceIp"));
        addField.accept("platform", clientInfoParameters.get("platform"));
        addField.accept("externalInstituteId", clientInfoParameters.get("externalInstituteId"));
        addField.accept("sessionId", clientInfoParameters.get("sessionId"));
        addField.accept("deviceId", clientInfoParameters.get("deviceId"));
        addField.accept("specRevision", clientInfoParameters.get("specRevision"));


// ... repeat for all fields

        String stringRequestBody = mapper.writeValueAsString(requestBody);

        /*// Build JSON request body
        String requestBody = String.format(
                "{\"username\":\"%s\"," +
                        "\"password\":\"%s\"," +
                        "\"realm\":\"%s\"," +
                        "\"locale\":\"%s\"," +
                        "\"customerType\":\"%s\"," +
                        "\"customerSubType\":\"%s\"," +
                        "\"serviceType\":\"%s\"," +
                        "\"channel\":\"%s\"," +
                        "\"macAddress\":\"%s\"," +
                        "\"imei\":\"%s\"," +
                        "\"imsi\":\"%s\"," +
                        "\"deviceIp\":\"%s\"," +
                        "\"platform\":\"%s\"," +
                        "\"externalInstituteId\":\"%s\"," +
                        "\"sessionId\":\"%s\"," +
                        "\"deviceId\":\"%s\"," +
                        "\"specRevision\":\"%s\"}",
                username,
                password,
                realmName,
                clientInfoParameters.get("locale"),
                clientInfoParameters.get("customerType"),
                clientInfoParameters.get("customerSubType"),
                clientInfoParameters.get("serviceType"),
                clientInfoParameters.get("channel"),
                clientInfoParameters.get("macAddress"),
                clientInfoParameters.get("imei"),
                clientInfoParameters.get("imsi"),
                clientInfoParameters.get("deviceIp"),
                clientInfoParameters.get("platform"),
                clientInfoParameters.get("externalInstituteId"),
                clientInfoParameters.get("sessionId"),
                clientInfoParameters.get("deviceId"),
                clientInfoParameters.get("specRevision")
        );*/

        // Create HTTP request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:7099/authentication-service/api/v1/auth/external/password"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(stringRequestBody))
                .timeout(Duration.ofSeconds(60))
                .build();

        // Send request and get response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Check response status
        return response;

    }
}

