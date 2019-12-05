package org.wso2.carbon.identity.application.authenticator.weblogic.oauth2.internal;

import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.user.core.service.RealmService;

public class WeblogicOauth2AuthenticatorDataHolder {

    private static WeblogicOauth2AuthenticatorDataHolder instance =
            new WeblogicOauth2AuthenticatorDataHolder();

    private RealmService realmService;

    private ClaimMetadataManagementService claimMetadataManagementService;

    private WeblogicOauth2AuthenticatorDataHolder() {}

    public static WeblogicOauth2AuthenticatorDataHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public ClaimMetadataManagementService getClaimMetadataManagementService() {
        return claimMetadataManagementService;
    }

    public void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {
        this.claimMetadataManagementService = claimMetadataManagementService;
    }
}
