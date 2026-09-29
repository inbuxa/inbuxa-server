/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use common::auth::AccessToken;
use jmap_proto::{
    method::set::SetRequest,
    object::JmapObject,
    request::{
        CopyRequestMethod, GetRequestMethod, ParseRequestMethod, QueryChangesRequestMethod,
        QueryRequestMethod, RequestMethod, SetRequestMethod, method::MethodObject,
        reference::MaybeResultReference,
    },
};
use registry::schema::enums::Permission;
use types::{collection::Collection, id::Id};

pub trait JmapAuthorization {
    fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self>;
    /// inbuxa: AL-8: the account's own, or a delegate allowed to send as it.
    fn assert_can_send(&self, account_id: Id) -> trc::Result<&Self>;
    fn assert_has_jmap_permission(
        &self,
        request: &RequestMethod,
        object: MethodObject,
    ) -> trc::Result<()>;
    fn assert_has_access(&self, to_account_id: Id, to_collection: Collection)
    -> trc::Result<&Self>;
}

impl JmapAuthorization for AccessToken {
    fn assert_can_send(&self, account_id: Id) -> trc::Result<&Self> {
        if self
            .delegation(account_id.document_id())
            .is_some_and(|delegation| delegation.send_as)
        {
            Ok(self)
        } else {
            self.assert_is_member(account_id)
        }
    }

    fn assert_is_member(&self, account_id: Id) -> trc::Result<&Self> {
        if self.is_member(account_id.document_id()) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details(format!("You are not an owner of account {}", account_id)))
        }
    }

    fn assert_has_access(
        &self,
        to_account_id: Id,
        to_collection: Collection,
    ) -> trc::Result<&Self> {
        if self.has_access(to_account_id.document_id(), to_collection) {
            Ok(self)
        } else {
            Err(trc::JmapEvent::Forbidden.into_err().details(format!(
                "You do not have access to account {}",
                to_account_id
            )))
        }
    }

    fn assert_has_jmap_permission(
        &self,
        request: &RequestMethod,
        object: MethodObject,
    ) -> trc::Result<()> {
        let permission = match request {
            RequestMethod::Get(m) => match &m {
                GetRequestMethod::Email(_) => Permission::JmapEmailGet,
                GetRequestMethod::Mailbox(_) => Permission::JmapMailboxGet,
                GetRequestMethod::Thread(_) => Permission::JmapThreadGet,
                GetRequestMethod::Identity(_) => Permission::JmapIdentityGet,
                GetRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionGet,
                GetRequestMethod::PushSubscription(_) => Permission::JmapPushSubscriptionGet,
                GetRequestMethod::Sieve(_) => Permission::JmapSieveScriptGet,
                GetRequestMethod::VacationResponse(_) => Permission::JmapVacationResponseGet,
                // inbuxa: Fastmail's MaskedEmail (ME-18)
                GetRequestMethod::MaskedEmail(_) => Permission::SysMaskedEmailGet,
                // inbuxa: deleted accounts (UD-17)
                GetRequestMethod::DeletedAccount(_) => Permission::SysAccountGet,
                // inbuxa: AI call limits, with the classifier's permissions
                GetRequestMethod::AiLimits(_) => Permission::SysSpamLlmGet,
                // inbuxa: log file retention, with the tracers' permissions
                GetRequestMethod::LogSettings(_) => Permission::SysTracerGet,
                // inbuxa: personal-data catalog, the inventory and its history
                GetRequestMethod::DataInventory(_) | GetRequestMethod::InventorySnapshot(_) => {
                    Permission::SysComplianceGet
                }
                // inbuxa: the audit log (AU-9)
                GetRequestMethod::AuditEvent(_) | GetRequestMethod::AuditSettings(_) => {
                    Permission::SysAuditGet
                }
                // inbuxa: account lock (AL-12)
                GetRequestMethod::AccountLock(_) => Permission::SysAccountLockGet,
                GetRequestMethod::LegalHold(_) => Permission::SysLegalHoldGet,
                // inbuxa: DLP and mail flow rules share an object; either
                // permission reaches it, and the handler shows each kind
                // only to those who may see it
                GetRequestMethod::MailRule(_) => {
                    if self.has_permission(Permission::SysMailRuleGet) {
                        Permission::SysMailRuleGet
                    } else {
                        Permission::SysDlpPolicyGet
                    }
                }
                GetRequestMethod::HoldExport(_) => Permission::SysLegalHoldExport,
                // inbuxa: legacy protocols off. It takes listeners away and
                // puts them back, so it takes the listener's permissions
                GetRequestMethod::ProtocolPolicy(_) => Permission::SysNetworkListenerGet,
                // inbuxa: legacy protocols off, per tenant. It governs
                // sign-in on the tenant's domains, so it takes the domain's
                // permissions, which a tenant administrator already holds.
                GetRequestMethod::TenantProtocolPolicy(_) => Permission::SysDomainGet,
                GetRequestMethod::Principal(_) => Permission::JmapPrincipalGet,
                GetRequestMethod::Quota(_) => Permission::JmapQuotaGet,
                GetRequestMethod::Blob(_) => Permission::JmapBlobGet,
                GetRequestMethod::AddressBook(_) => Permission::JmapAddressBookGet,
                GetRequestMethod::ContactCard(_) => Permission::JmapContactCardGet,
                GetRequestMethod::FileNode(_) => Permission::JmapFileNodeGet,
                GetRequestMethod::PrincipalAvailability(_) => {
                    Permission::JmapPrincipalGetAvailability
                }
                GetRequestMethod::Calendar(_) => Permission::JmapCalendarGet,
                GetRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventGet,
                GetRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationGet
                }
                GetRequestMethod::ParticipantIdentity(_) => Permission::JmapParticipantIdentityGet,
                GetRequestMethod::ShareNotification(_) => Permission::JmapShareNotificationGet,
                GetRequestMethod::Registry(_) => {
                    let MethodObject::Registry(object_type) = object else {
                        unreachable!()
                    };
                    // inbuxa: MT-2: server-level objects are out of a tenant's reach
                    assert_tenant_reach(
                        self,
                        inbuxa_features::tenancy::reach::can_read(object_type),
                    )?;
                    object_type.get_permission()
                }
            },
            RequestMethod::Set(m) => {
                return match &m {
                    SetRequestMethod::Email(s) => validate_set(
                        s,
                        self,
                        Permission::JmapEmailCreate,
                        Permission::JmapEmailUpdate,
                        Permission::JmapEmailDestroy,
                    ),
                    SetRequestMethod::Mailbox(s) => validate_set(
                        s,
                        self,
                        Permission::JmapMailboxCreate,
                        Permission::JmapMailboxUpdate,
                        Permission::JmapMailboxDestroy,
                    ),
                    SetRequestMethod::Identity(s) => validate_set(
                        s,
                        self,
                        Permission::JmapIdentityCreate,
                        Permission::JmapIdentityUpdate,
                        Permission::JmapIdentityDestroy,
                    ),
                    SetRequestMethod::EmailSubmission(s) => validate_set(
                        s,
                        self,
                        Permission::JmapEmailSubmissionCreate,
                        Permission::JmapEmailSubmissionUpdate,
                        Permission::JmapEmailSubmissionDestroy,
                    ),
                    SetRequestMethod::PushSubscription(s) => validate_set(
                        s,
                        self,
                        Permission::JmapPushSubscriptionCreate,
                        Permission::JmapPushSubscriptionUpdate,
                        Permission::JmapPushSubscriptionDestroy,
                    ),
                    SetRequestMethod::Sieve(s) => validate_set(
                        s,
                        self,
                        Permission::JmapSieveScriptCreate,
                        Permission::JmapSieveScriptUpdate,
                        Permission::JmapSieveScriptDestroy,
                    ),
                    // inbuxa: Fastmail's MaskedEmail (ME-18)
                    SetRequestMethod::MaskedEmail(s) => validate_set(
                        s,
                        self,
                        Permission::SysMaskedEmailCreate,
                        Permission::SysMaskedEmailUpdate,
                        Permission::SysMaskedEmailDestroy,
                    ),
                    // inbuxa: deleted accounts; a restore creates the account again (UD-17)
                    SetRequestMethod::DeletedAccount(s) => validate_set(
                        s,
                        self,
                        Permission::SysAccountCreate,
                        Permission::SysAccountCreate,
                        Permission::SysAccountDestroy,
                    ),
                    // inbuxa: AI call limits, with the classifier's permissions
                    SetRequestMethod::AiLimits(s) => validate_set(
                        s,
                        self,
                        Permission::SysSpamLlmUpdate,
                        Permission::SysSpamLlmUpdate,
                        Permission::SysSpamLlmUpdate,
                    ),
                    // inbuxa: log file retention, with the tracers' permissions
                    SetRequestMethod::LogSettings(s) => validate_set(
                        s,
                        self,
                        Permission::SysTracerUpdate,
                        Permission::SysTracerUpdate,
                        Permission::SysTracerUpdate,
                    ),
                    // inbuxa: the audit log (AU-7, AU-9, AU-11)
                    SetRequestMethod::AuditSettings(s) => validate_set(
                        s,
                        self,
                        Permission::SysAuditSettingsUpdate,
                        Permission::SysAuditSettingsUpdate,
                        Permission::SysAuditSettingsUpdate,
                    ),
                    SetRequestMethod::AuditExport(s) => validate_set(
                        s,
                        self,
                        Permission::SysAuditExport,
                        Permission::SysAuditExport,
                        Permission::SysAuditExport,
                    ),
                    // inbuxa: account lock (AL-12)
                    SetRequestMethod::AccountLock(s) => validate_set(
                        s,
                        self,
                        Permission::SysAccountLockCreate,
                        Permission::SysAccountLockUpdate,
                        Permission::SysAccountLockDestroy,
                    ),
                    // inbuxa: legal hold (LH-13); holds are never destroyed,
                    // and the handler refuses a destroy outright
                    SetRequestMethod::LegalHold(s) => validate_set(
                        s,
                        self,
                        Permission::SysLegalHoldCreate,
                        Permission::SysLegalHoldUpdate,
                        Permission::SysLegalHoldUpdate,
                    ),
                    // inbuxa: DLP and mail flow rules: either change
                    // permission gets in; the handler checks each rule's kind
                    SetRequestMethod::MailRule(_) => {
                        if self.has_permission(Permission::SysMailRuleUpdate)
                            || self.has_permission(Permission::SysDlpPolicyUpdate)
                        {
                            Ok(())
                        } else {
                            Err(trc::JmapEvent::Forbidden
                                .into_err()
                                .details("You are not authorized to change mail rules"))
                        }
                    }
                    // inbuxa: LH-12, exporting held data
                    SetRequestMethod::HoldExport(s) => validate_set(
                        s,
                        self,
                        Permission::SysLegalHoldExport,
                        Permission::SysLegalHoldExport,
                        Permission::SysLegalHoldExport,
                    ),
                    SetRequestMethod::AuditVerification(s) => validate_set(
                        s,
                        self,
                        Permission::SysAuditGet,
                        Permission::SysAuditGet,
                        Permission::SysAuditGet,
                    ),
                    // inbuxa: "Explain this" (EX-4)
                    SetRequestMethod::Explanation(s) => validate_set(
                        s,
                        self,
                        Permission::SysAiExplain,
                        Permission::SysAiExplain,
                        Permission::SysAiExplain,
                    ),
                    // inbuxa: legacy protocols off, with the listener's
                    SetRequestMethod::ProtocolPolicy(s) => validate_set(
                        s,
                        self,
                        Permission::SysNetworkListenerUpdate,
                        Permission::SysNetworkListenerUpdate,
                        Permission::SysNetworkListenerUpdate,
                    ),
                    // inbuxa: legacy protocols off, per tenant, with the domain's
                    SetRequestMethod::TenantProtocolPolicy(s) => validate_set(
                        s,
                        self,
                        Permission::SysDomainUpdate,
                        Permission::SysDomainUpdate,
                        Permission::SysDomainUpdate,
                    ),
                    SetRequestMethod::VacationResponse(s) => validate_set(
                        s,
                        self,
                        Permission::JmapVacationResponseCreate,
                        Permission::JmapVacationResponseUpdate,
                        Permission::JmapVacationResponseDestroy,
                    ),
                    SetRequestMethod::AddressBook(s) => validate_set(
                        s,
                        self,
                        Permission::JmapAddressBookCreate,
                        Permission::JmapAddressBookUpdate,
                        Permission::JmapAddressBookDestroy,
                    ),
                    SetRequestMethod::ContactCard(s) => validate_set(
                        s,
                        self,
                        Permission::JmapContactCardCreate,
                        Permission::JmapContactCardUpdate,
                        Permission::JmapContactCardDestroy,
                    ),
                    SetRequestMethod::FileNode(s) => validate_set(
                        s,
                        self,
                        Permission::JmapFileNodeCreate,
                        Permission::JmapFileNodeUpdate,
                        Permission::JmapFileNodeDestroy,
                    ),
                    SetRequestMethod::ShareNotification(s) => validate_set(
                        s,
                        self,
                        Permission::JmapShareNotificationCreate,
                        Permission::JmapShareNotificationUpdate,
                        Permission::JmapShareNotificationDestroy,
                    ),
                    SetRequestMethod::Calendar(s) => validate_set(
                        s,
                        self,
                        Permission::JmapCalendarCreate,
                        Permission::JmapCalendarUpdate,
                        Permission::JmapCalendarDestroy,
                    ),
                    SetRequestMethod::CalendarEvent(s) => validate_set(
                        s,
                        self,
                        Permission::JmapCalendarEventCreate,
                        Permission::JmapCalendarEventUpdate,
                        Permission::JmapCalendarEventDestroy,
                    ),
                    SetRequestMethod::CalendarEventNotification(s) => validate_set(
                        s,
                        self,
                        Permission::JmapCalendarEventNotificationCreate,
                        Permission::JmapCalendarEventNotificationUpdate,
                        Permission::JmapCalendarEventNotificationDestroy,
                    ),
                    SetRequestMethod::ParticipantIdentity(s) => validate_set(
                        s,
                        self,
                        Permission::JmapParticipantIdentityCreate,
                        Permission::JmapParticipantIdentityUpdate,
                        Permission::JmapParticipantIdentityDestroy,
                    ),
                    SetRequestMethod::Registry(s) => {
                        let MethodObject::Registry(object_type) = object else {
                            unreachable!()
                        };
                        // inbuxa: MT-2, MT-12: server-level objects are out of a tenant's reach
                        assert_tenant_reach(
                            self,
                            inbuxa_features::tenancy::reach::can_write(object_type),
                        )?;
                        let set_permissions = object_type.set_permission();
                        validate_set(
                            s,
                            self,
                            set_permissions[0],
                            set_permissions[1],
                            set_permissions[2],
                        )
                    }
                };
            }
            RequestMethod::Changes(_) => match object {
                MethodObject::Email => Permission::JmapEmailChanges,
                MethodObject::Mailbox => Permission::JmapMailboxChanges,
                MethodObject::Thread => Permission::JmapThreadChanges,
                MethodObject::Identity => Permission::JmapIdentityChanges,
                MethodObject::EmailSubmission => Permission::JmapEmailSubmissionChanges,
                MethodObject::Quota => Permission::JmapQuotaChanges,
                MethodObject::ContactCard => Permission::JmapContactCardChanges,
                MethodObject::FileNode => Permission::JmapFileNodeChanges,
                MethodObject::Calendar => Permission::JmapCalendarChanges,
                MethodObject::CalendarEvent => Permission::JmapCalendarEventChanges,
                MethodObject::CalendarEventNotification => {
                    Permission::JmapCalendarEventNotificationChanges
                }
                MethodObject::ParticipantIdentity => Permission::JmapParticipantIdentityChanges,
                MethodObject::ShareNotification => Permission::JmapShareNotificationChanges,
                MethodObject::Principal => Permission::JmapPrincipalChanges,
                MethodObject::AddressBook => Permission::JmapAddressBookChanges,
                MethodObject::Core
                | MethodObject::Blob
                | MethodObject::PushSubscription
                | MethodObject::SearchSnippet
                | MethodObject::VacationResponse
                | MethodObject::SieveScript
                | MethodObject::MaskedEmail
                | MethodObject::DeletedAccount
                | MethodObject::AiLimits
                | MethodObject::LogSettings
                | MethodObject::DataInventory
                | MethodObject::InventorySnapshot
                | MethodObject::Explanation
                | MethodObject::AuditEvent
                | MethodObject::AuditSettings
                | MethodObject::AuditExport
                | MethodObject::AuditVerification
                | MethodObject::AccountLock
                | MethodObject::LegalHold
                | MethodObject::HoldExport
                | MethodObject::MailRule
                | MethodObject::ProtocolPolicy
                | MethodObject::TenantProtocolPolicy => Permission::JmapEmailChanges,
                // inbuxa: x:MaskedEmail/changes reads what /get reads
                MethodObject::Registry(object_type) => object_type.get_permission(),
            },
            RequestMethod::Copy(m) => match &m {
                CopyRequestMethod::Email(_) => Permission::JmapEmailCopy,
                CopyRequestMethod::Blob(_) => Permission::JmapBlobCopy,
                CopyRequestMethod::ContactCard(_) => Permission::JmapContactCardCopy,
                CopyRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventCopy,
                CopyRequestMethod::FileNode(_) => Permission::JmapFileNodeCopy,
            },
            RequestMethod::ImportEmail(_) => Permission::JmapEmailImport,
            RequestMethod::Parse(m) => match &m {
                ParseRequestMethod::Email(_) => Permission::JmapEmailParse,
                ParseRequestMethod::ContactCard(_) => Permission::JmapContactCardParse,
                ParseRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventParse,
            },
            RequestMethod::QueryChanges(m) => match m {
                QueryChangesRequestMethod::Email(_) => Permission::JmapEmailQueryChanges,
                QueryChangesRequestMethod::Mailbox(_) => Permission::JmapMailboxQueryChanges,
                QueryChangesRequestMethod::EmailSubmission(_) => {
                    Permission::JmapEmailSubmissionQueryChanges
                }
                QueryChangesRequestMethod::Principal(_) => Permission::JmapPrincipalQueryChanges,
                QueryChangesRequestMethod::Quota(_) => Permission::JmapQuotaQueryChanges,
                QueryChangesRequestMethod::ContactCard(_) => {
                    Permission::JmapContactCardQueryChanges
                }
                QueryChangesRequestMethod::FileNode(_) => Permission::JmapFileNodeQueryChanges,
                QueryChangesRequestMethod::CalendarEvent(_) => {
                    Permission::JmapCalendarEventQueryChanges
                }
                QueryChangesRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationQueryChanges
                }
                QueryChangesRequestMethod::ShareNotification(_) => {
                    Permission::JmapShareNotificationQueryChanges
                }
            },
            RequestMethod::Query(m) => match m {
                QueryRequestMethod::Email(_) => Permission::JmapEmailQuery,
                QueryRequestMethod::Mailbox(_) => Permission::JmapMailboxQuery,
                QueryRequestMethod::EmailSubmission(_) => Permission::JmapEmailSubmissionQuery,
                QueryRequestMethod::Sieve(_) => Permission::JmapSieveScriptQuery,
                QueryRequestMethod::Principal(_) => Permission::JmapPrincipalQuery,
                QueryRequestMethod::Quota(_) => Permission::JmapQuotaQuery,
                QueryRequestMethod::AddressBook(_) => Permission::JmapAddressBookGet,
                QueryRequestMethod::ContactCard(_) => Permission::JmapContactCardQuery,
                QueryRequestMethod::FileNode(_) => Permission::JmapFileNodeQuery,
                QueryRequestMethod::Calendar(_) => Permission::JmapCalendarGet,
                QueryRequestMethod::CalendarEvent(_) => Permission::JmapCalendarEventQuery,
                QueryRequestMethod::CalendarEventNotification(_) => {
                    Permission::JmapCalendarEventNotificationQuery
                }
                QueryRequestMethod::ShareNotification(_) => Permission::JmapShareNotificationQuery,
                // inbuxa: the audit log (AU-9)
                QueryRequestMethod::AuditEvent(_) => Permission::SysAuditGet,
                QueryRequestMethod::Registry(_) => {
                    let MethodObject::Registry(object_type) = object else {
                        unreachable!()
                    };
                    // inbuxa: MT-2: server-level objects are out of a tenant's reach
                    assert_tenant_reach(
                        self,
                        inbuxa_features::tenancy::reach::can_read(object_type),
                    )?;
                    object_type.query_permission()
                }
            },
            RequestMethod::SearchSnippet(_) => Permission::JmapSearchSnippetGet,
            RequestMethod::ValidateScript(_) => Permission::JmapSieveScriptValidate,
            RequestMethod::LookupBlob(_) => Permission::JmapBlobLookup,
            RequestMethod::UploadBlob(_) => Permission::JmapBlobUpload,
            RequestMethod::Echo(_) => Permission::JmapCoreEcho,
            RequestMethod::Error(_) => return Ok(()),
        };

        if self.has_permission(permission) {
            Ok(())
        } else {
            Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("You are not authorized to perform this action"))
        }
    }
}

// inbuxa: MT-2
fn assert_tenant_reach(access_token: &AccessToken, reachable: bool) -> trc::Result<()> {
    if reachable || access_token.tenant_id().is_none() {
        Ok(())
    } else {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to perform this action"))
    }
}

fn validate_set<T: JmapObject>(
    set: &SetRequest<'_, T>,
    access_token: &AccessToken,
    create_permission: Permission,
    update_permission: Permission,
    destroy_permission: Permission,
) -> trc::Result<()> {
    let can_create = access_token.has_permission(create_permission);
    let can_update = access_token.has_permission(update_permission);
    let can_destroy = access_token.has_permission(destroy_permission);

    if can_create && can_update && can_destroy {
        Ok(())
    } else if !can_create && !can_update && !can_destroy {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to create, update or destroy objects of this type"))
    } else if !can_create && set.create.as_ref().is_some_and(|objs| !objs.is_empty()) {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to create objects of this type"))
    } else if !can_update && set.update.as_ref().is_some_and(|objs| !objs.is_empty()) {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to update objects of this type"))
    } else if !can_destroy
        && set.destroy.as_ref().is_some_and(|objs| match objs {
            MaybeResultReference::Value(v) => !v.is_empty(),
            MaybeResultReference::Reference(_) => true,
        })
    {
        Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("You are not authorized to destroy objects of this type"))
    } else {
        Ok(())
    }
}
