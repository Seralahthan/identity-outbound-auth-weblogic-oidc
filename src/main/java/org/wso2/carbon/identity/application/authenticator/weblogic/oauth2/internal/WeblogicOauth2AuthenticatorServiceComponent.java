package org.wso2.carbon.identity.application.authenticator.weblogic.oauth2.internal;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.weblogic.oauth2.WeblogicOauth2Authenticator;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "identity.application.authenticator.weblogic.oauth2.component",
        immediate = true
)
public class WeblogicOauth2AuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(WeblogicOauth2AuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            WeblogicOauth2Authenticator weblogicOauth2Authenticator = new WeblogicOauth2Authenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    weblogicOauth2Authenticator, null);
            if (log.isDebugEnabled()) {
                log.debug("Weblogic OAuth2 Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating Weblogic OAuth2 Authenticator", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Weblogic OAuth2 Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        WeblogicOauth2AuthenticatorDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service");
        }
        WeblogicOauth2AuthenticatorDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "claim.manager.listener.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimManagementService"
    )
    protected void setClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {
        WeblogicOauth2AuthenticatorDataHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);
    }

    protected void unsetClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {
        WeblogicOauth2AuthenticatorDataHolder.getInstance()
                .setClaimMetadataManagementService(null);
    }
}
