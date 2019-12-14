package org.wso2.carbon.identity.application.authenticator.weblogic.oauth2;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.*;

public class WeblogicOauth2Authenticator extends OpenIDConnectAuthenticator
        implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(WeblogicOauth2Authenticator.class);

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {

            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);

            // Create OAuth client that uses custom http client under the hood
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOauthResponse(oAuthClient, accessTokenRequest);

            String accessToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN);

            if (StringUtils.isBlank(accessToken)) {
                throw new AuthenticationFailedException("Access token is empty or null");
            }

//            String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

            context.setProperty(OIDCAuthenticatorConstants.ACCESS_TOKEN, accessToken);

            AuthenticatedUser authenticatedUser;
            Map<ClaimMapping, String> claims = new HashMap<>();
            Map<String, Object> jsonObject = new HashMap<>();

            String userInfoFields = authenticatorProperties.get(WeblogicOauth2AuthenticatorConstants.USER_INFO_FIELDS);
            String userInfoUrl = getUserInfoEndpoint(oAuthResponse, authenticatorProperties);

            ClaimConfig claimConfig = getAuthenticatorClaimConfigurations(context);
            if (claimConfig == null) {
                throw new AuthenticationFailedException("Authenticator " + getName() + " returned null when " +
                        "obtaining claim configurations");
            }

            if (StringUtils.isBlank(userInfoUrl)) {
                throw new AuthenticationFailedException("User Info Endpoint URL is empty or null");
            }


            jsonObject = getUserInfoJson(userInfoUrl, userInfoFields, accessToken);
            authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                    getAuthenticateUser(context, jsonObject, oAuthResponse));

            claims.putAll(buildClaims(jsonObject));
            authenticatedUser.setUserAttributes(claims);

            context.setSubject(authenticatedUser);

        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication process failed.", context.getSubject(), e);
        } catch (ApplicationAuthenticatorException e) {
            log.error("Authentication process failed.", e);
            throw new AuthenticationFailedException(e.getMessage(), context.getSubject(), e);
        }
    }

    /**
     *
     * @param request
     * @param response
     * @param context
     */
    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) {
        log.debug("Handled logout response from service provider " + request.getParameter("sp") +
                " in tenant domain " + request.getParameter("tenantDomain"));
    }

    protected String getLogoutUrl(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(WeblogicOauth2AuthenticatorConstants.IDP_LOGOUT_URL);
    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws LogoutFailedException {
        if (isLogoutEnabled(context)) {
            String logoutUrl = getLogoutUrl(context.getAuthenticatorProperties());

            Map<String, String> paramMap = new HashMap<>();

            try {
                logoutUrl = FrameworkUtils.buildURLWithQueryParams(logoutUrl, paramMap);
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                String idpName = context.getExternalIdP().getName();
                String tenantDomain = context.getTenantDomain();
                throw new LogoutFailedException("Error occured while initiating the logout request to IdP: " + idpName
                        + " of tenantDomain: " + tenantDomain, e);
            }
        } else {
            super.initiateLogoutRequest(request, response, context);
        }
    }

    private boolean isLogoutEnabled(AuthenticationContext context) {
        String logoutUrl = getLogoutUrl(context.getAuthenticatorProperties());
        return StringUtils.isNotBlank(logoutUrl);
    }

    protected Map<ClaimMapping, String> buildClaims(Map<String, Object> jsonObject) {

        Map<ClaimMapping, String> claims = new HashMap<>();
        for (Map.Entry<String, Object> data : jsonObject.entrySet()) {
            String key = data.getKey();
            Object valueObject = data.getValue();

            if (valueObject != null) {
                String value;
                if (valueObject instanceof Object[]) {
                    value = StringUtils.join((Object[]) valueObject, FrameworkUtils.getMultiAttributeSeparator());
                } else {
                    value = valueObject.toString();
                }
                claims.put(ClaimMapping.build(key, key, null, false), value);
            }

            if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)
                    && jsonObject.get(key) != null) {
                log.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key)
                        .toString());
            }
        }
        return claims;
    }

    @Override
    public String getFriendlyName() {
        return "Weblogic OAuth2 Connect";
    }

    @Override
    public String getName() {
        return WeblogicOauth2AuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * This method get idp claim configurations
     * @param context
     * @return ClaimConfig
     */
    private ClaimConfig getAuthenticatorClaimConfigurations(AuthenticationContext context) {
        ClaimConfig claimConfig = null;
        if (context != null) {
            ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
            if (externalIdPConfig != null) {
                IdentityProvider identityProvider = externalIdPConfig.getIdentityProvider();
                if (identityProvider != null) {
                    claimConfig = identityProvider.getClaimConfig();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Authenticator " + getName() + " recieved null IdentityProvider");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticator " + getName() + " recieved null ExternalIdPConfig");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Authenticator " + getName() + " recieved null AuthenticationContext");
            }
        }
        return claimConfig;
    }

    /**
     *
     * @param context
     * @param oidcClaims
     * @param oidcResponse
     * @return
     */
    @Override
    protected String getAuthenticateUser(AuthenticationContext context, Map<String, Object> oidcClaims,
                                         OAuthClientResponse oidcResponse) {
        return (String) oidcClaims.get(WeblogicOauth2AuthenticatorConstants.DEFAULT_USER_IDENTIFIER);
    }

    /**
     *
     * @param userInfoUrl
     * @param userInfoFields
     * @param accessToken
     * @return
     * @throws ApplicationAuthenticatorException
     */
    protected Map<String, Object> getUserInfoJson(String userInfoUrl, String userInfoFields, String accessToken)
        throws ApplicationAuthenticatorException {
        Map<String, Object> filteredJsonObject = new HashMap<>();
        String userInfoString = getUserInfoString(userInfoUrl, userInfoFields, accessToken);

        if (StringUtils.isBlank(userInfoString)) {
            if (log.isDebugEnabled()) {
                log.debug("Empty JSON response from user info endpoint. Unable to fetch user claims" +
                        " Proceeding without user claims");
            }
            throw new ApplicationAuthenticatorException("Empty JSON response from the user info endpoint");
        }
        Map<String, Object> jsonObject = JSONUtils.parseJSON(userInfoString);
        if (!jsonObject.containsKey(WeblogicOauth2AuthenticatorConstants.DEFAULT_USER_IDENTIFIER)) {
            throw new ApplicationAuthenticatorException("User subject identifier not found.");
        }

        for(String k : Arrays.asList(userInfoFields.split(","))) {
            if(jsonObject.containsKey(k)) {
                filteredJsonObject.put(k, jsonObject.get(k));
            }
        }
         return filteredJsonObject;
    }

    /**
     *
     * @param userInfoUrl
     * @param userInfoFields
     * @param accessToken
     * @return
     * @throws ApplicationAuthenticatorException
     */
    protected String getUserInfoString(String userInfoUrl, String userInfoFields, String accessToken)
        throws ApplicationAuthenticatorException {
        String userInfoString;
        try {
            userInfoString = sendRequest(String.format("%s?access_token=%s", userInfoUrl, accessToken));
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("URL : " + userInfoUrl, e);
            }
            throw new ApplicationAuthenticatorException("MalformedURLException while sending user information request.",
                    e);
        } catch (IOException e) {
            throw new ApplicationAuthenticatorException("IOException while sending sending user information request.",
                    e);
        }
        return userInfoString;
    }

    protected String sendRequest(String url) throws IOException {

        BufferedReader in = null;
        StringBuilder b = new StringBuilder();

        try {
            URLConnection urlConnection = new URL(url).openConnection();
            in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), Charset.forName("utf-8")));

            String inputLine = in.readLine();
            while (inputLine != null) {
                b.append(inputLine).append("\n");
                inputLine = in.readLine();
            }
        } finally {
            IdentityIOStreamUtils.closeReader(in);
        }

        return b.toString();
    }

    /**
     * Get Configuration Properties
     *
     * @return
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter OAuth2 Connect client identifier value");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter OAuth2 Connect client secret value");
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property authorizationEndpointUrl = new Property();
        authorizationEndpointUrl.setDisplayName("Authorization Endpoint URL");
        authorizationEndpointUrl.setRequired(true);
        authorizationEndpointUrl.setName(IdentityApplicationConstants.OAuth2.OAUTH2_AUTHZ_URL);
        authorizationEndpointUrl.setDescription("Enter OAuth2 Connect authorization endpoint URL value");
        authorizationEndpointUrl.setDisplayOrder(3);
        configProperties.add(authorizationEndpointUrl);

        Property tokenEndpointUrl = new Property();
        tokenEndpointUrl.setDisplayName("Token Endpoint URL:");
        tokenEndpointUrl.setRequired(true);
        tokenEndpointUrl.setName(IdentityApplicationConstants.OAuth2.OAUTH2_TOKEN_URL);
        tokenEndpointUrl.setDescription("Enter OAuth2 Connect token endpoint URL value");
        tokenEndpointUrl.setDisplayOrder(4);
        configProperties.add(tokenEndpointUrl);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setName(IdentityApplicationConstants.OAuth2.CALLBACK_URL);
        callbackUrl.setDescription("Enter value corresponding to callback url");
        callbackUrl.setDisplayOrder(5);
        configProperties.add(callbackUrl);

        Property userinfoEndpointUrl = new Property();
        userinfoEndpointUrl.setDisplayName("Userinfo Endpoint URL");
        userinfoEndpointUrl.setName(IdentityApplicationConstants.Authenticator.OIDC.USER_INFO_URL);
        userinfoEndpointUrl.setDescription("Enter value corresponding to userinfo endpoint url");
        userinfoEndpointUrl.setDisplayOrder(6);
        configProperties.add(userinfoEndpointUrl);

        Property idpLogoutUrl = new Property();
        idpLogoutUrl.setDisplayName("Logout URL");
        idpLogoutUrl.setName(WeblogicOauth2AuthenticatorConstants.IDP_LOGOUT_URL);
        idpLogoutUrl.setDescription("Enter value corresponding to the logout url");
        idpLogoutUrl.setDisplayOrder(7);
        configProperties.add(idpLogoutUrl);

        Property scope = new Property();
        scope.setDisplayName("Additional Query Parameters");
        scope.setName("AdditionalQueryParameters");
//        scope.setValue("scope=openid email profile");
        scope.setDescription("Additional query parameters. e.g: paramName1=value1");
        scope.setDisplayOrder(8);
        configProperties.add(scope);

        Property userinfoFields = new Property();
        userinfoFields.setDisplayName("User Information Fields");
        userinfoFields.setName(WeblogicOauth2AuthenticatorConstants.USER_INFO_FIELDS);
        userinfoFields.setDescription("Enter comma-separated user information fields you want to retrieve");
        userinfoFields.setDisplayOrder(9);
        configProperties.add(userinfoFields);

        Property isBasicAuthEnabled = new Property();
        isBasicAuthEnabled.setDisplayName("Enable HTTP basic auth for client authentication");
        isBasicAuthEnabled.setName(OIDCAuthenticatorConstants.IS_BASIC_AUTH_ENABLED);
        isBasicAuthEnabled.setValue("false");
        isBasicAuthEnabled.setDefaultValue("false");
        isBasicAuthEnabled.setDescription("Specifies that HTTP basic authentication should be used for client " +
                "authentication, else client credentials will be included in the request body ");
        isBasicAuthEnabled.setDisplayOrder(10);
        configProperties.add(isBasicAuthEnabled);

        return configProperties;
    }

}

