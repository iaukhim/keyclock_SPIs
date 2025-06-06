package com.example.keycloak.pin_grant;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.protocol.oidc.grants.ResourceOwnerPasswordCredentialsGrantType;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.ResourceOwnerPasswordCredentialsContext;
import org.keycloak.services.clientpolicy.context.ResourceOwnerPasswordCredentialsResponseContext;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.TokenUtil;


public class PinGrantType extends OAuth2GrantTypeBase {

    private static final Logger logger = Logger.getLogger(ResourceOwnerPasswordCredentialsGrantType.class);

    @Override
    public Response process(Context context) {
        setContext(context);

        event.detail(Details.AUTH_METHOD, "oauth_credentials");
        logger.log(Logger.Level.ERROR, formParams);
        System.out.println("FORM_PARAMS = " + formParams);

        if (!client.isDirectAccessGrantsEnabled()) {
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNAUTHORIZED_CLIENT, "Client not allowed for direct access grants", Response.Status.BAD_REQUEST);
        }

        if (client.isConsentRequired()) {
            event.error(Errors.CONSENT_DENIED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT, "Client requires user consent", Response.Status.BAD_REQUEST);
        }

        try {
            session.clientPolicy().triggerOnEvent(new ResourceOwnerPasswordCredentialsContext(formParams));
        } catch (ClientPolicyException cpe) {
            event.error(cpe.getError());
            throw new CorsErrorResponseException(cors, cpe.getError(), cpe.getErrorDetail(), cpe.getErrorStatus());
        }

        String scope = getRequestedScopes();

        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        realm.getAuthenticationFlowsStream()
                .forEach(flow  -> System.out.println("I got such flow as " + flow.getAlias()));
        AuthenticationFlowModel flow =  realm.getFlowByAlias("direct_grant_pin");

        /*AuthenticationProcessor processor = new AuthenticationProcessor()
                .setFlowId(flow.getId())
                .setAuthenticationSession(authSession);*/

        String flowId = flow.getId();
        AuthenticationProcessor processor = new AuthenticationProcessor();
        processor.setAuthenticationSession(authSession)
                .setFlowId(flowId)
                .setFlowPath("token")
                .setConnection(clientConnection)
                .setEventBuilder(event)
                .setRealm(realm)
                .setSession(session)
                .setUriInfo(session.getContext().getUri())
                .setRequest(request);



       /* event.error(Errors.RESOLVE_REQUIRED_ACTIONS);
        logger.log(Logger.Level.ERROR, formParams);
        System.out.println("FORM_PARAMS = " + formParams);

        String username = formParams.getFirst("username");
        String password = formParams.getFirst("password");
        String pin = formParams.getFirst("pin");

        System.out.println(String.format("CUSTOM_PIN authentication attempt. Username = %s, password = %s, pin = %s", username, password, pin));


        UserModel userByUsername = session.users().getUserByUsername(realm, username);
        if (userByUsername != null) {
            Map<String, List<String>> attributes = userByUsername.getAttributes();
            System.out.println("attributes = " +
                    attributes
            );
            String savedPin = attributes.get("pin").get(0);
            if (!savedPin.equals(pin)) {
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "PIN is incorrect", Response.Status.BAD_REQUEST);
            }
            processor.setAutheticatedUser(userByUsername);
        }*/

        Response challenge = processor.authenticateOnly();
        if (challenge != null) {
            // Remove authentication session as "Resource Owner Password Credentials Grant" is single-request scoped authentication
            new AuthenticationSessionManager(session).removeAuthenticationSession(realm, authSession, false);
            cors.build(response);
            return challenge;
        }
        processor.evaluateRequiredActionTriggers();
        UserModel user = authSession.getAuthenticatedUser();
        System.out.println("user = " + user.getAttributes());
        if (user.getRequiredActionsStream().count() > 0 || authSession.getRequiredActions().size() > 0) {
            // Remove authentication session as "Resource Owner Password Credentials Grant" is single-request scoped authentication
            new AuthenticationSessionManager(session).removeAuthenticationSession(realm, authSession, false);
            event.error(Errors.RESOLVE_REQUIRED_ACTIONS);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "Account is not fully set up", Response.Status.BAD_REQUEST);

        }

        AuthenticationManager.setClientScopesInSession(authSession);

        ClientSessionContext clientSessionCtx = processor.attachSession();
        UserSessionModel userSession = processor.getUserSession();
        updateUserSessionFromClientAuth(userSession);

        TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager
                .responseBuilder(realm, client, event, session, userSession, clientSessionCtx).generateAccessToken();
        boolean useRefreshToken = clientConfig.isUseRefreshToken();
        if (useRefreshToken) {
            responseBuilder.generateRefreshToken();
        }

        String scopeParam = clientSessionCtx.getClientSession().getNote(OAuth2Constants.SCOPE);
        if (TokenUtil.isOIDCRequest(scopeParam)) {
            responseBuilder.generateIDToken().generateAccessTokenHash();
        }

        checkAndBindMtlsHoKToken(responseBuilder, useRefreshToken);

        try {
            session.clientPolicy().triggerOnEvent(new ResourceOwnerPasswordCredentialsResponseContext(formParams, clientSessionCtx, responseBuilder));
        } catch (ClientPolicyException cpe) {
            event.error(cpe.getError());
            throw new CorsErrorResponseException(cors, cpe.getError(), cpe.getErrorDetail(), cpe.getErrorStatus());
        }

        AccessTokenResponse res = responseBuilder.build();

        event.success();
        AuthenticationManager.logSuccess(session, authSession);

        return cors.builder(Response.ok(res, MediaType.APPLICATION_JSON_TYPE)).build();
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

}
