/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

use crate::{
    addressbook::{get::AddressBookGet, set::AddressBookSet},
    api::auth::JmapAuthorization,
    blob::{copy::BlobCopy, get::BlobOperations, upload::BlobUpload},
    calendar::{get::CalendarGet, set::CalendarSet},
    calendar_event::{
        copy::JmapCalendarEventCopy, get::CalendarEventGet, parse::CalendarEventParse,
        query::CalendarEventQuery, set::CalendarEventSet,
    },
    calendar_event_notification::{
        get::CalendarEventNotificationGet, query::CalendarEventNotificationQuery,
        set::CalendarEventNotificationSet,
    },
    changes::{get::ChangesLookup, query::QueryChanges},
    contact::{
        copy::JmapContactCardCopy, get::ContactCardGet, parse::ContactCardParse,
        query::ContactCardQuery, set::ContactCardSet,
    },
    email::{
        copy::JmapEmailCopy, get::EmailGet, import::EmailImport, parse::EmailParse,
        query::EmailQuery, set::EmailSet, snippet::EmailSearchSnippet,
    },
    file::{copy::FileNodeCopy, get::FileNodeGet, query::FileNodeQuery, set::FileNodeSet},
    identity::{get::IdentityGet, set::IdentitySet},
    mailbox::{get::MailboxGet, query::MailboxQuery, set::MailboxSet},
    participant_identity::{get::ParticipantIdentityGet, set::ParticipantIdentitySet},
    principal::{availability::PrincipalGetAvailability, get::PrincipalGet, query::PrincipalQuery},
    push::{get::PushSubscriptionFetch, set::PushSubscriptionSet},
    quota::{get::QuotaGet, query::QuotaQuery},
    registry::{get::RegistryGet, query::RegistryQuery, set::RegistrySet},
    share_notification::{
        get::ShareNotificationGet, query::ShareNotificationQuery, set::ShareNotificationSet,
    },
    sieve::{
        get::SieveScriptGet, query::SieveScriptQuery, set::SieveScriptSet,
        validate::SieveScriptValidate,
    },
    submission::{get::EmailSubmissionGet, query::EmailSubmissionQuery, set::EmailSubmissionSet},
    thread::get::ThreadGet,
    vacation::{get::VacationResponseGet, set::VacationResponseSet},
};
use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    request::{
        Call, CopyRequestMethod, GetRequestMethod, INVALID_ACCOUNT_ID, ParseRequestMethod,
        QueryRequestMethod, Request, RequestMethod, SetRequestMethod,
        capability::Capability,
        method::{MethodName, MethodObject},
    },
    response::{Response, ResponseMethod, SetResponseMethod},
};
use std::future::Future;
use std::time::Instant;
use trc::JmapEvent;
use types::{collection::Collection, id::Id};

pub trait RequestHandler: Sync + Send {
    fn handle_jmap_request<'x>(
        &self,
        request: Request<'x>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = Response<'x>> + Send;

    fn handle_method_call<'x>(
        &self,
        method: RequestMethod<'x>,
        method_name: MethodName,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<ResponseMethod<'x>>> + Send;
}

impl RequestHandler for Server {
    async fn handle_jmap_request<'x>(
        &self,
        request: Request<'x>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> Response<'x> {
        let add_created_ids = request.created_ids.is_some();
        let using = request.using;
        let mut response = Response::new(
            access_token.state(),
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );

        // inbuxa: ST-6: reads before the request's first write may go to a
        // read replica
        let mut has_written = false;

        for mut call in request.method_calls {
            // Resolve result and id references
            if let Err(error) = response.resolve_references(&mut call.method) {
                let method_error = error.clone();

                trc::error!(error.span_id(session.session_id));

                response.push_response(call.id, MethodName::error(), method_error);
                continue;
            }

            if !matches!(call.method, RequestMethod::Error(_)) {
                let capability = call.name.obj.capability();
                if capability != Capability::Stalwart && !using.contains(capability) {
                    response.push_response(
                        call.id,
                        MethodName::error(),
                        trc::JmapEvent::UnknownMethod.into_err().details(format!(
                            "Method {} requires capability {} which is not present in the \"using\" property.",
                            call.name,
                            capability.as_str()
                        )),
                    );
                    continue;
                }
            }

            loop {
                let mut next_call = None;

                // Add response
                let method_name = call.name.as_str();

                // inbuxa: ST-6, ST-7: a read before the first write may use a
                // replica that has every change the client has seen
                let eligible = !has_written
                    && matches!(
                        call.method,
                        RequestMethod::Get(_)
                            | RequestMethod::Query(_)
                            | RequestMethod::Changes(_)
                            | RequestMethod::QueryChanges(_)
                    );
                let is_write = matches!(
                    call.method,
                    RequestMethod::Set(_)
                        | RequestMethod::Copy(_)
                        | RequestMethod::ImportEmail(_)
                        | RequestMethod::UploadBlob(_)
                );
                if is_write {
                    has_written = true;
                }
                // inbuxa: AL-7: what a delegate makes in a locked account
                // may need the lock's grants
                let makes_containers = is_write
                    && matches!(
                        call.name.obj,
                        MethodObject::Mailbox
                            | MethodObject::Calendar
                            | MethodObject::AddressBook
                            | MethodObject::FileNode
                    );
                let call_name = call.name.as_str().into_owned();
                let presented = match &call.method {
                    RequestMethod::Changes(changes) => match &changes.since_state {
                        jmap_proto::types::state::State::Exact(change_id) => {
                            Some((changes.account_id.document_id(), *change_id))
                        }
                        _ => None,
                    },
                    _ => None,
                };
                // inbuxa: AU-1.6: which accounts it reached by impersonation
                let method_call = crate::inbuxa::audit::collect_access(Box::pin(
                    self.handle_method_call(
                        call.method,
                        call.name,
                        access_token,
                        &mut next_call,
                        session,
                    ),
                ));
                let result = if eligible {
                    store::backend::scaleout::replica::replica_read(
                        access_token.all_ids().map(|account_id| {
                            (
                                account_id,
                                presented
                                    .filter(|(id, _)| *id == account_id)
                                    .map_or(0, |(_, change_id)| change_id),
                            )
                        }),
                        method_call,
                    )
                    .await
                } else {
                    method_call.await
                };
                let (result, reached) = result;
                for account_id in reached {
                    // inbuxa: AL-9: a delegate's access, and what it
                    // changes, are recorded; anyone else here impersonated
                    if let Some(delegation) = access_token.delegation(account_id) {
                        // MA-S: in a shared mailbox only what is sent as it
                        // is recorded (audit_send_as); every read and flag
                        // on a busy desk would bury the log
                        if delegation.kind.is_lock() {
                            let access = delegation.access.as_str();
                            self.audit_delegate(
                                access_token,
                                account_id,
                                access,
                                is_write.then_some(call_name.as_str()),
                                result.as_ref().err(),
                            )
                            .await;
                        }
                        if makes_containers
                            && result.is_ok()
                            && let Err(err) =
                                email::inbuxa_lock::reconcile(self, account_id).await
                        {
                            trc::error!(err.details("Failed to grant a lock's delegates on new folders"));
                        }
                    } else {
                        self.audit_foreign_access(access_token, account_id, false).await;
                    }
                }
                match result
                {
                    Ok(mut method_response) => {
                        match &mut method_response {
                            ResponseMethod::Set(set_response) => {
                                // Add created ids
                                match set_response {
                                    SetResponseMethod::Email(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Mailbox(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Identity(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::EmailSubmission(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::PushSubscription(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Sieve(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::VacationResponse(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::MaskedEmail(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::DeletedAccount(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::AiLimits(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::LogSettings(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::DlpSettings(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::AuditSettings(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::AuditExport(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::AuditVerification(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::AccountLock(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::LegalHold(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::MailRule(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::SecurityAcceptance(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::DeliverabilityReport(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::DeliverabilitySettings(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::ReportExport(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::ScheduledReport(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::ScheduledReportSettings(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Journal(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::JournalExport(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::JournalVerification(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::HeldMessage(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::HoldExport(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Explanation(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::ProtocolPolicy(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::TenantProtocolPolicy(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::SharingPolicy(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::AddressBook(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::ContactCard(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::FileNode(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::ShareNotification(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Calendar(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::CalendarEvent(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::ParticipantIdentity(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::CalendarEventNotification(_) => {}
                                    SetResponseMethod::Registry(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                }
                            }
                            ResponseMethod::ImportEmail(import_response) => {
                                // Add created ids
                                import_response.update_created_ids(&mut response);
                            }
                            ResponseMethod::UploadBlob(upload_response) => {
                                // Add created blobIds
                                upload_response.update_created_ids(&mut response);
                            }
                            _ => {}
                        }

                        response.push_response(call.id, call.name, method_response);
                    }
                    Err(error) => {
                        let method_error = error.clone();

                        trc::error!(
                            error
                                .span_id(session.session_id)
                                .ctx_unique(trc::Key::AccountId, access_token.account_id())
                                .caused_by(method_name)
                        );

                        response.push_error(call.id, method_error);
                    }
                }

                // Process next call
                if let Some(next_call) = next_call {
                    call = next_call;
                    call.id
                        .clone_from(&response.method_responses.last().unwrap().id);
                } else {
                    break;
                }
            }
        }

        if !add_created_ids {
            response.created_ids.clear();
        }

        response
    }

    async fn handle_method_call<'x>(
        &self,
        method: RequestMethod<'x>,
        method_name: MethodName,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> trc::Result<ResponseMethod<'x>> {
        let op_start = Instant::now();

        // Check permissions
        access_token.assert_has_jmap_permission(&method, method_name.obj)?;

        // Handle method
        let response = match method {
            RequestMethod::Get(req) => match req {
                GetRequestMethod::Email(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_get(*req, access_token).await?.into()
                }
                GetRequestMethod::Mailbox(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_get(*req, access_token).await?.into()
                }
                GetRequestMethod::Thread(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.thread_get(*req, access_token).await?.into()
                }
                GetRequestMethod::Identity(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AL-8: a delegate may send as a locked account
                    access_token.assert_can_send(req.account_id)?;

                    self.identity_get(*req).await?.into()
                }
                GetRequestMethod::EmailSubmission(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AL-8: a delegate may send as a locked account
                    access_token.assert_can_send(req.account_id)?;

                    self.email_submission_get(*req).await?.into()
                }
                GetRequestMethod::PushSubscription(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    self.push_subscription_get(*req, access_token).await?.into()
                }
                GetRequestMethod::Sieve(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.sieve_script_get(*req).await?.into()
                }
                GetRequestMethod::VacationResponse(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.vacation_response_get(*req).await?.into()
                }
                // inbuxa: Fastmail's MaskedEmail/get
                GetRequestMethod::MaskedEmail(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::fastmail::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:DeletedAccount/get (UD-17)
                GetRequestMethod::DeletedAccount(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::deleted_account::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:AiLimits/get
                GetRequestMethod::AiLimits(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::ai_limits::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:LogSettings/get
                GetRequestMethod::LogSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::log_settings::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:DlpSettings/get
                GetRequestMethod::DlpSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::dlp_settings::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:DataInventory/get
                GetRequestMethod::DataInventory(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::data_inventory::inventory_get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:InventorySnapshot/get
                GetRequestMethod::InventorySnapshot(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::data_inventory::snapshot_get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: account lock with delegation (AL-1)
                GetRequestMethod::AccountLock(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::account_lock::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: legal hold (LH-1)
                // inbuxa: legal hold exports (LH-12)
                GetRequestMethod::HoldExport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::hold_export_api::get(self, *req).await?.into()
                }
                GetRequestMethod::LegalHold(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::legal_hold::get(self, *req).await?.into()
                }
                // inbuxa: mail held for review
                GetRequestMethod::HeldMessage(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::held_message::get(self, access_token, *req).await?.into()
                }
                // inbuxa: DLP and mail flow rules
                GetRequestMethod::MailRule(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::mail_rule::get(self, access_token, *req).await?.into()
                }
                // inbuxa: accepted security to-do items
                GetRequestMethod::SecurityAcceptance(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::security_acceptance::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: the deliverability check
                GetRequestMethod::DeliverabilityReport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::deliverability::get_reports(self, access_token, *req)
                        .await?
                        .into()
                }
                GetRequestMethod::DeliverabilitySettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::deliverability::get_settings(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: scheduled reports
                GetRequestMethod::ScheduledReport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::scheduled_reports::get_reports(self, access_token, *req)
                        .await?
                        .into()
                }
                GetRequestMethod::ScheduledReportSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::scheduled_reports::get_settings(self, access_token, *req)
                        .await?
                        .into()
                }
                GetRequestMethod::ReportExport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::scheduled_reports::get_exports(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: journaling
                GetRequestMethod::Journal(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::journal::get(self, access_token, *req).await?.into()
                }
                GetRequestMethod::JournalEntry(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::journal_entry::get(self, access_token, session, *req)
                        .await?
                        .into()
                }
                // inbuxa: the audit log (AU-9)
                GetRequestMethod::AuditEvent(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit_log::event_get(self, access_token, *req)
                        .await?
                        .into()
                }
                GetRequestMethod::AuditSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit_log::settings_get(self, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:ProtocolPolicy/get (legacy protocols off)
                GetRequestMethod::ProtocolPolicy(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::protocol_policy::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:TenantProtocolPolicy/get (legacy protocols off, per tenant)
                GetRequestMethod::TenantProtocolPolicy(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::tenant_protocol_policy::get(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:SharingPolicy/get (MA-C, who may share mail)
                GetRequestMethod::SharingPolicy(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::sharing_policy::get(self, access_token, *req)
                        .await?
                        .into()
                }
                GetRequestMethod::Principal(req) => {
                    self.principal_get(*req, access_token).await?.into()
                }
                GetRequestMethod::Quota(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.quota_get(*req, access_token).await?.into()
                }
                GetRequestMethod::Blob(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.blob_get(*req, access_token).await?.into()
                }
                GetRequestMethod::AddressBook(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::AddressBook)?;

                    self.address_book_get(*req, access_token).await?.into()
                }
                GetRequestMethod::ContactCard(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::ContactCard)?;

                    self.contact_card_get(*req, access_token).await?.into()
                }
                GetRequestMethod::FileNode(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::FileNode)?;

                    self.file_node_get(*req, access_token).await?.into()
                }
                GetRequestMethod::PrincipalAvailability(req) => self
                    .principal_get_availability(*req, access_token)
                    .await?
                    .into(),
                GetRequestMethod::Calendar(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Calendar)?;

                    self.calendar_get(*req, access_token).await?.into()
                }
                GetRequestMethod::CalendarEvent(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::CalendarEvent)?;

                    self.calendar_event_get(*req, access_token).await?.into()
                }
                GetRequestMethod::CalendarEventNotification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.calendar_event_notification_get(*req, access_token)
                        .await?
                        .into()
                }
                GetRequestMethod::ParticipantIdentity(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.participant_identity_get(*req).await?.into()
                }
                GetRequestMethod::ShareNotification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.share_notification_get(*req).await?.into()
                }
                GetRequestMethod::Registry(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    assert_registry_account(self, method_name.obj, access_token, req.account_id)
                        .await?;

                    Box::pin(self.registry_get(
                        method_name.obj.unwrap_registry(),
                        *req,
                        access_token,
                    ))
                    .await?
                    .into()
                }
            },
            RequestMethod::Query(req) => match req {
                QueryRequestMethod::Email(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::Mailbox(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::EmailSubmission(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AL-8: a delegate may send as a locked account
                    access_token.assert_can_send(req.account_id)?;

                    self.email_submission_query(*req).await?.into()
                }
                QueryRequestMethod::Sieve(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.sieve_script_query(*req).await?.into()
                }
                QueryRequestMethod::Principal(req) => {
                    self.principal_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::Quota(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.quota_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::AddressBook(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::AddressBook)?;

                    self.address_book_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::ContactCard(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::ContactCard)?;

                    self.contact_card_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::FileNode(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::FileNode)?;

                    self.file_node_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::Calendar(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Calendar)?;

                    self.calendar_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::CalendarEvent(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::CalendarEvent)?;

                    self.calendar_event_query(*req, access_token).await?.into()
                }
                QueryRequestMethod::CalendarEventNotification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.calendar_event_notification_query(*req, access_token)
                        .await?
                        .into()
                }
                QueryRequestMethod::ShareNotification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.share_notification_query(*req).await?.into()
                }
                // inbuxa: the audit log (AU-9)
                QueryRequestMethod::AuditEvent(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit_log::event_query(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: journaling (JR-15)
                QueryRequestMethod::JournalEntry(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::journal_entry::query(self, access_token, session, *req)
                        .await?
                        .into()
                }
                QueryRequestMethod::Registry(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    assert_registry_account(self, method_name.obj, access_token, req.account_id)
                        .await?;

                    Box::pin(self.registry_query(
                        method_name.obj.unwrap_registry(),
                        *req,
                        access_token,
                    ))
                    .await?
                    .into()
                }
            },
            RequestMethod::Set(req) => match req {
                SetRequestMethod::Email(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_set(*req, access_token, session).await?.into()
                }
                SetRequestMethod::Mailbox(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_set(*req, access_token).await?.into()
                }
                SetRequestMethod::Identity(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.identity_set(*req).await?.into()
                }
                SetRequestMethod::EmailSubmission(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AL-8: a delegate may send as a locked account
                    access_token.assert_can_send(req.account_id)?;

                    self.email_submission_set(*req, access_token, &session.instance, next_call)
                        .await?
                        .into()
                }
                SetRequestMethod::PushSubscription(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    self.push_subscription_set(*req, access_token).await?.into()
                }
                SetRequestMethod::Sieve(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.sieve_script_set(*req, access_token, session)
                        .await?
                        .into()
                }
                SetRequestMethod::VacationResponse(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.vacation_response_set(*req, access_token).await?.into()
                }
                // inbuxa: Fastmail's MaskedEmail/set
                SetRequestMethod::MaskedEmail(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::fastmail::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: inbuxa:DeletedAccount/set (UD-17)
                SetRequestMethod::DeletedAccount(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::deleted_account::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: inbuxa:AiLimits/set
                SetRequestMethod::AiLimits(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::ai_limits::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: inbuxa:LogSettings/set
                SetRequestMethod::LogSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::log_settings::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: inbuxa:DlpSettings/set
                SetRequestMethod::DlpSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::dlp_settings::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: the audit log (AU-7, AU-11, AU-6)
                SetRequestMethod::AuditSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::audit_log::settings_set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: account lock with delegation, recorded with its
                // reason (AL-1, AU-12)
                SetRequestMethod::AccountLock(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    let reason = req.arguments.reason.clone().or_else(|| {
                        req.create.as_ref().and_then(|create| {
                            create.values().find_map(|value| {
                                serde_json::to_value(value)
                                    .ok()?
                                    .get("reason")?
                                    .as_str()
                                    .map(str::to_string)
                            })
                        })
                    });
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        reason,
                        *req,
                        |req| Box::pin(crate::inbuxa::account_lock::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: legal hold (LH-1), each change recorded with its
                // reason (AU-12)
                // inbuxa: legal hold exports, recorded with their reason
                // (AU-1.9, AU-12)
                SetRequestMethod::HoldExport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    let reason = req.arguments.reason.clone().or_else(|| {
                        req.create.as_ref().and_then(|create| {
                            create.values().find_map(|value| {
                                serde_json::to_value(value)
                                    .ok()?
                                    .get("reason")?
                                    .as_str()
                                    .map(str::to_string)
                            })
                        })
                    });
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        reason,
                        *req,
                        |req| Box::pin(crate::inbuxa::hold_export_api::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                SetRequestMethod::LegalHold(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    let reason = req.arguments.reason.clone().or_else(|| {
                        req.create.as_ref().and_then(|create| {
                            create.values().find_map(|value| {
                                serde_json::to_value(value)
                                    .ok()?
                                    .get("reason")?
                                    .as_str()
                                    .map(str::to_string)
                            })
                        })
                    });
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        reason,
                        *req,
                        |req| Box::pin(crate::inbuxa::legal_hold::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                SetRequestMethod::HeldMessage(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    let reason = req.arguments.reason.clone();
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        reason,
                        *req,
                        |req| Box::pin(crate::inbuxa::held_message::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                SetRequestMethod::MailRule(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    let reason = req.arguments.reason.clone();
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        reason,
                        *req,
                        |req| Box::pin(crate::inbuxa::mail_rule::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: SS-26, every acceptance made or removed is in the
                // audit log
                SetRequestMethod::SecurityAcceptance(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| {
                            Box::pin(crate::inbuxa::security_acceptance::set(
                                self,
                                access_token,
                                req,
                            ))
                        },
                    )
                    .await?
                    .into()
                }
                // inbuxa: DL-15, Check now; nothing it changes needs recording
                SetRequestMethod::DeliverabilityReport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::deliverability::set_reports(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: scheduled reports; every change is in the audit log
                SetRequestMethod::ScheduledReport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| {
                            Box::pin(crate::inbuxa::scheduled_reports::set_reports(
                                self,
                                access_token,
                                req,
                            ))
                        },
                    )
                    .await?
                    .into()
                }
                // inbuxa: RP-19; a download is in the audit log too
                SetRequestMethod::ReportExport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| {
                            Box::pin(crate::inbuxa::scheduled_reports::set_exports(
                                self,
                                access_token,
                                req,
                            ))
                        },
                    )
                    .await?
                    .into()
                }
                SetRequestMethod::ScheduledReportSettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| {
                            Box::pin(crate::inbuxa::scheduled_reports::set_settings(
                                self,
                                access_token,
                                req,
                            ))
                        },
                    )
                    .await?
                    .into()
                }
                // inbuxa: DL-6; which lists are asked is in the audit log
                SetRequestMethod::DeliverabilitySettings(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| {
                            Box::pin(crate::inbuxa::deliverability::set_settings(
                                self,
                                access_token,
                                req,
                            ))
                        },
                    )
                    .await?
                    .into()
                }
                SetRequestMethod::Journal(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    let reason = req.arguments.reason.clone();
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        reason,
                        *req,
                        |req| Box::pin(crate::inbuxa::journal::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                SetRequestMethod::AuditExport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit_log::export_set(self, access_token, session, *req)
                        .await?
                        .into()
                }
                SetRequestMethod::AuditVerification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::audit_log::verification_set(self, access_token, session, *req)
                        .await?
                        .into()
                }
                // inbuxa: journaling (JR-6, JR-16)
                SetRequestMethod::JournalExport(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::journal_entry::export_set(self, access_token, session, *req)
                        .await?
                        .into()
                }
                SetRequestMethod::JournalVerification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::journal_entry::verification_set(self, access_token, session, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:Explanation/set ("Explain this")
                SetRequestMethod::Explanation(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    crate::inbuxa::explanation::set(self, access_token, *req)
                        .await?
                        .into()
                }
                // inbuxa: inbuxa:ProtocolPolicy/set (legacy protocols off)
                SetRequestMethod::ProtocolPolicy(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::protocol_policy::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: inbuxa:TenantProtocolPolicy/set (legacy protocols off, per tenant)
                SetRequestMethod::TenantProtocolPolicy(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::tenant_protocol_policy::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                // inbuxa: inbuxa:SharingPolicy/set (MA-C, who may share mail)
                SetRequestMethod::SharingPolicy(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    // inbuxa: AU-1.2, AU-3
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        None,
                        None,
                        *req,
                        |req| Box::pin(crate::inbuxa::sharing_policy::set(self, access_token, req)),
                    )
                    .await?
                    .into()
                }
                SetRequestMethod::AddressBook(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::AddressBook)?;

                    self.address_book_set(*req, access_token, session)
                        .await?
                        .into()
                }
                SetRequestMethod::ContactCard(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::ContactCard)?;

                    self.contact_card_set(*req, access_token, session)
                        .await?
                        .into()
                }
                SetRequestMethod::FileNode(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::FileNode)?;

                    self.file_node_set(*req, access_token, session)
                        .await?
                        .into()
                }
                SetRequestMethod::ShareNotification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.share_notification_set(*req).await?.into()
                }
                SetRequestMethod::Calendar(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Calendar)?;

                    self.calendar_set(*req, access_token, session).await?.into()
                }
                SetRequestMethod::CalendarEvent(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::CalendarEvent)?;

                    self.calendar_event_set(*req, access_token, session)
                        .await?
                        .into()
                }
                SetRequestMethod::CalendarEventNotification(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.calendar_event_notification_set(*req, access_token, session)
                        .await?
                        .into()
                }
                SetRequestMethod::ParticipantIdentity(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.participant_identity_set(*req).await?.into()
                }
                SetRequestMethod::Registry(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    assert_registry_account(self, method_name.obj, access_token, req.account_id)
                        .await?;

                    // inbuxa: AU-1.1, AU-3: recorded before and after
                    let object_type = method_name.obj.unwrap_registry();
                    crate::inbuxa::audit::recorded(
                        self,
                        access_token,
                        session,
                        &method_name.obj.to_string(),
                        Some(object_type),
                        None,
                        *req,
                        |req| Box::pin(self.registry_set(object_type, req, access_token, session)),
                    )
                    .await?
                    .into()
                }
            },
            RequestMethod::Changes(mut req) => {
                resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;

                // inbuxa: x:MaskedEmail/changes and x:ArchivedItem/changes
                if method_name.obj
                    == MethodObject::Registry(registry::schema::prelude::ObjectType::ArchivedItem)
                {
                    crate::inbuxa::undelete::changes(self, access_token, *req).await?
                } else if matches!(method_name.obj, MethodObject::Registry(_)) {
                    crate::inbuxa::masked_email::changes(self, access_token, *req).await?
                } else {
                    self.changes(*req, method_name.obj, access_token)
                        .await?
                        .into_method_response()
                }
            }
            RequestMethod::Copy(req) => match req {
                CopyRequestMethod::Email(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    resolve_account_id(&mut req.from_account_id, method_name.obj, access_token)?;

                    access_token
                        .assert_has_access(req.account_id, Collection::Email)?
                        .assert_has_access(req.from_account_id, Collection::Email)?;

                    self.email_copy(*req, access_token, next_call, session)
                        .await?
                        .into()
                }
                CopyRequestMethod::Blob(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_is_member(req.account_id)?;

                    self.blob_copy(*req, access_token).await?.into()
                }
                CopyRequestMethod::ContactCard(mut req) => {
                    resolve_account_id(&mut req.from_account_id, method_name.obj, access_token)?;
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;

                    access_token
                        .assert_has_access(req.account_id, Collection::ContactCard)?
                        .assert_has_access(req.from_account_id, Collection::ContactCard)?;

                    self.contact_card_copy(*req, access_token, next_call, session)
                        .await?
                        .into()
                }
                CopyRequestMethod::CalendarEvent(mut req) => {
                    resolve_account_id(&mut req.from_account_id, method_name.obj, access_token)?;
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;

                    access_token
                        .assert_has_access(req.account_id, Collection::CalendarEvent)?
                        .assert_has_access(req.from_account_id, Collection::CalendarEvent)?;

                    self.calendar_event_copy(*req, access_token, next_call, session)
                        .await?
                        .into()
                }
                CopyRequestMethod::FileNode(mut req) => {
                    resolve_account_id(&mut req.from_account_id, method_name.obj, access_token)?;
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;

                    access_token
                        .assert_has_access(req.account_id, Collection::FileNode)?
                        .assert_has_access(req.from_account_id, Collection::FileNode)?;

                    self.file_node_copy(*req, access_token, next_call, session)
                        .await?
                        .into()
                }
            },
            RequestMethod::ImportEmail(mut req) => {
                resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                access_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_import(*req, access_token, session).await?.into()
            }
            RequestMethod::Parse(req) => match req {
                ParseRequestMethod::Email(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_parse(*req, access_token).await?.into()
                }
                ParseRequestMethod::ContactCard(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::ContactCard)?;

                    self.contact_card_parse(*req, access_token).await?.into()
                }
                ParseRequestMethod::CalendarEvent(mut req) => {
                    resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                    access_token.assert_has_access(req.account_id, Collection::CalendarEvent)?;

                    self.calendar_event_parse(*req, access_token).await?.into()
                }
            },
            RequestMethod::QueryChanges(req) => self.query_changes(req, access_token).await?.into(),
            RequestMethod::SearchSnippet(mut req) => {
                resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                access_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_search_snippet(*req, access_token).await?.into()
            }
            RequestMethod::ValidateScript(mut req) => {
                resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                access_token.assert_is_member(req.account_id)?;

                self.sieve_script_validate(*req, access_token).await?.into()
            }
            RequestMethod::LookupBlob(mut req) => {
                resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                access_token.assert_is_member(req.account_id)?;

                self.blob_lookup(*req).await?.into()
            }
            RequestMethod::UploadBlob(mut req) => {
                resolve_account_id(&mut req.account_id, method_name.obj, access_token)?;
                access_token.assert_is_member(req.account_id)?;

                self.blob_upload_many(*req, access_token).await?.into()
            }
            RequestMethod::Echo(req) => req.into(),
            RequestMethod::Error(error) => return Err(error),
        };

        trc::event!(
            Jmap(JmapEvent::MethodCall),
            Id = method_name.as_str(),
            SpanId = session.session_id,
            AccountId = access_token.account_id(),
            Elapsed = op_start.elapsed(),
        );

        Ok(response)
    }
}

// inbuxa: ME-19: a tenant administrator reaches the masks of its tenant's
// accounts without impersonate, and a tenant principal never reaches beyond
// its tenant
async fn assert_registry_account(
    server: &Server,
    obj: MethodObject,
    access_token: &AccessToken,
    account_id: Id,
) -> trc::Result<()> {
    if matches!(
        obj,
        MethodObject::Registry(
            registry::schema::prelude::ObjectType::MaskedEmail
                | registry::schema::prelude::ObjectType::ArchivedItem
        )
    ) {
        crate::inbuxa::masked_email::assert_can_manage(
            server,
            access_token,
            account_id.document_id(),
        )
        .await
    } else {
        access_token.assert_is_member(account_id).map(|_| ())
    }
}

pub(crate) fn resolve_account_id(
    account_id: &mut Id,
    obj: MethodObject,
    access_token: &AccessToken,
) -> trc::Result<()> {
    if account_id.id() < INVALID_ACCOUNT_ID {
        // inbuxa: AU-1.6
        crate::inbuxa::audit::note_access(account_id.document_id(), access_token);
        Ok(())
    } else if matches!(
        obj,
        MethodObject::Core | MethodObject::PushSubscription | MethodObject::Registry(_)
    ) {
        *account_id = Id::from(access_token.account_id());
        Ok(())
    } else if account_id.id() == INVALID_ACCOUNT_ID {
        Err(trc::JmapEvent::AccountNotFound.into_err())
    } else {
        Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("The \"accountId\" property is required."))
    }
}
