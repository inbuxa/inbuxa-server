# SPDX-FileCopyrightText: 2026 Coffey Labs LLC
# SPDX-License-Identifier: AGPL-3.0-only
"""
Everything in the generated Rust code that schema.json does not say.

Each table below is a special case: information upstream's (private)
generator takes from its own source definitions and which the published
schema file leaves out. They were recovered from the generated reference
files of upstream v1.0.0 (Enterprise-stripped, commit d1e48ba) and are
documented one by one. generate.py reads nothing else besides the schema.
"""

# ===========================================================================
# 1. Names
# ===========================================================================

# Enums that schema.json lists but that are not generated in enums.rs:
# the generated code refers to a type defined elsewhere instead (value), or
# the enum only serves JMAP (non-"x:") objects, which are not generated (None).
EXTERNAL_ENUMS = {
    'EventType': 'trc::EventType',
    'MetricType': 'trc::MetricType',
    'Key': 'trc::Key',
    'IncludeInAvailability': None,
}

# The fork renamed some upstream strings (tools/fork/renames.py) in the
# schema and in generated string literals, but not in Rust identifiers.
# Identifiers are therefore built from the pre-rename name.
IDENT_SOURCE_NAMES = {
    'vnd.inbuxa.while': 'vnd.stalwart.while',
    'vnd.inbuxa.expressions': 'vnd.stalwart.expressions',
}

# schema_oss.json.gz was not run through the fork's renames; map its names
# onto schema.json's when telling open enum variants from Enterprise ones.
OSS_NAME_RENAMES = {
    'vnd.stalwart.while': 'vnd.inbuxa.while',
    'vnd.stalwart.expressions': 'vnd.inbuxa.expressions',
}

# Property names whose `Property` variant is not just the capitalized name.
PROPERTY_IDENTS = {}

# Enums that get a `pub const ALL: &[Self]` list.
ENUMS_WITH_ALL = ['Permission', 'TaskType']

# ===========================================================================
# 2. Expression contexts (enums.rs statics)
# ===========================================================================

# Which variables / constants each expression context allows. The schema
# lists ExpressionVariable and ExpressionConstant but not these groupings.
EXPRESSION_STATICS = [
    ('HTTP_VARIABLE', 'ExpressionVariable', [
        'Listener', 'RemoteIp', 'RemotePort', 'LocalIp', 'LocalPort',
        'Protocol', 'IsTls', 'Url', 'Path', 'Headers', 'Method',
    ]),
    ('MTA_CONNECTION_VARIABLE', 'ExpressionVariable', [
        'Listener', 'RemoteIp', 'RemotePort', 'LocalIp', 'LocalPort',
        'Protocol', 'IsTls', 'Asn', 'Country',
    ]),
    ('MTA_EHLO_VARIABLE', 'ExpressionVariable', [
        'Listener', 'RemoteIp', 'RemotePort', 'LocalIp', 'LocalPort',
        'Protocol', 'IsTls', 'HeloDomain', 'Asn', 'Country',
    ]),
    ('MTA_MAIL_FROM_VARIABLE', 'ExpressionVariable', [
        'Listener', 'RemoteIp', 'RemotePort', 'LocalIp', 'LocalPort',
        'Protocol', 'IsTls', 'Sender', 'SenderDomain', 'AuthenticatedAs',
        'Asn', 'Country',
    ]),
    ('MTA_QUEUE_HOST_VARIABLE', 'ExpressionVariable', [
        'Sender', 'SenderDomain', 'RcptDomain', 'Rcpt', 'Recipients', 'Mx',
        'Priority', 'RemoteIp', 'LocalIp', 'RetryNum', 'NotifyNum',
        'ExpiresIn', 'LastStatus', 'LastError', 'QueueName', 'QueueAge',
        'ReceivedFromIp', 'ReceivedViaPort', 'Source', 'Size',
    ]),
    ('MTA_QUEUE_RCPT_VARIABLE', 'ExpressionVariable', [
        'Rcpt', 'RcptDomain', 'Recipients', 'Sender', 'SenderDomain',
        'Priority', 'RetryNum', 'NotifyNum', 'ExpiresIn', 'LastStatus',
        'LastError', 'QueueName', 'QueueAge', 'ReceivedFromIp',
        'ReceivedViaPort', 'Source', 'Size',
    ]),
    ('MTA_QUEUE_SENDER_VARIABLE', 'ExpressionVariable', [
        'Sender', 'SenderDomain', 'Priority', 'Recipients',
    ]),
    ('MTA_RCPT_DOMAIN_VARIABLE', 'ExpressionVariable', [
        'RcptDomain',
    ]),
    ('MTA_RCPT_TO_VARIABLE', 'ExpressionVariable', [
        'Sender', 'SenderDomain', 'Recipients', 'Rcpt', 'RcptDomain',
        'AuthenticatedAs', 'Listener', 'RemoteIp', 'RemotePort', 'LocalIp',
        'LocalPort', 'Protocol', 'IsTls', 'Priority', 'HeloDomain', 'Asn',
        'Country',
    ]),
    ('MTA_RCPT_VARIABLE', 'ExpressionVariable', [
        'Rcpt',
    ]),
    ('SPAM_AI_VARIABLE', 'ExpressionVariable', [
        'SpamScore', 'SpamThreshold', 'RemoteIp', 'RemoteIpPtr', 'HeloDomain',
        'AuthenticatedAs', 'Asn', 'Country', 'IsTls', 'EnvFrom',
        'EnvFromLocal', 'EnvFromDomain', 'EnvTo', 'From', 'FromName',
        'FromLocal', 'FromDomain', 'ReplyTo', 'ReplyToName', 'ReplyToLocal',
        'ReplyToDomain', 'To', 'ToName', 'ToLocal', 'ToDomain', 'Cc', 'CcName',
        'CcLocal', 'CcDomain', 'Bcc', 'BccName', 'BccLocal', 'BccDomain',
        'Body', 'BodyText', 'BodyHtml', 'BodyWords', 'BodyRaw', 'Subject',
        'SubjectThread', 'SubjectWords', 'Location', 'SpamProbability',
    ]),
    ('SPAM_DEFAULT_VARIABLE', 'ExpressionVariable', [
        'RemoteIp', 'RemoteIpPtr', 'HeloDomain', 'AuthenticatedAs', 'Asn',
        'Country', 'IsTls', 'EnvFrom', 'EnvFromLocal', 'EnvFromDomain',
        'EnvTo', 'From', 'FromName', 'FromLocal', 'FromDomain', 'ReplyTo',
        'ReplyToName', 'ReplyToLocal', 'ReplyToDomain', 'To', 'ToName',
        'ToLocal', 'ToDomain', 'Cc', 'CcName', 'CcLocal', 'CcDomain', 'Bcc',
        'BccName', 'BccLocal', 'BccDomain', 'Body', 'BodyText', 'BodyHtml',
        'BodyWords', 'BodyRaw', 'Subject', 'SubjectThread', 'SubjectWords',
        'Location', 'SpamProbability',
    ]),
    ('SPAM_EMAIL_VARIABLE', 'ExpressionVariable', [
        'Email', 'Value', 'Name', 'Local', 'Domain', 'Sld', 'RemoteIp',
        'RemoteIpPtr', 'HeloDomain', 'AuthenticatedAs', 'Asn', 'Country',
        'IsTls', 'EnvFrom', 'EnvFromLocal', 'EnvFromDomain', 'EnvTo', 'From',
        'FromName', 'FromLocal', 'FromDomain', 'ReplyTo', 'ReplyToName',
        'ReplyToLocal', 'ReplyToDomain', 'To', 'ToName', 'ToLocal', 'ToDomain',
        'Cc', 'CcName', 'CcLocal', 'CcDomain', 'Bcc', 'BccName', 'BccLocal',
        'BccDomain', 'Body', 'BodyText', 'BodyHtml', 'BodyWords', 'BodyRaw',
        'Subject', 'SubjectThread', 'SubjectWords', 'Location',
        'SpamProbability',
    ]),
    ('SPAM_GENERIC_VARIABLE', 'ExpressionVariable', [
        'Value', 'RemoteIp', 'RemoteIpPtr', 'HeloDomain', 'AuthenticatedAs',
        'Asn', 'Country', 'IsTls', 'EnvFrom', 'EnvFromLocal', 'EnvFromDomain',
        'EnvTo', 'From', 'FromName', 'FromLocal', 'FromDomain', 'ReplyTo',
        'ReplyToName', 'ReplyToLocal', 'ReplyToDomain', 'To', 'ToName',
        'ToLocal', 'ToDomain', 'Cc', 'CcName', 'CcLocal', 'CcDomain', 'Bcc',
        'BccName', 'BccLocal', 'BccDomain', 'Body', 'BodyText', 'BodyHtml',
        'BodyWords', 'BodyRaw', 'Subject', 'SubjectThread', 'SubjectWords',
        'Location', 'SpamProbability',
    ]),
    ('SPAM_HEADER_VARIABLE', 'ExpressionVariable', [
        'Name', 'NameLower', 'Value', 'ValueLower', 'Attributes', 'Raw',
        'RawLower', 'RemoteIp', 'RemoteIpPtr', 'HeloDomain', 'AuthenticatedAs',
        'Asn', 'Country', 'IsTls', 'EnvFrom', 'EnvFromLocal', 'EnvFromDomain',
        'EnvTo', 'From', 'FromName', 'FromLocal', 'FromDomain', 'ReplyTo',
        'ReplyToName', 'ReplyToLocal', 'ReplyToDomain', 'To', 'ToName',
        'ToLocal', 'ToDomain', 'Cc', 'CcName', 'CcLocal', 'CcDomain', 'Bcc',
        'BccName', 'BccLocal', 'BccDomain', 'Body', 'BodyText', 'BodyHtml',
        'BodyWords', 'BodyRaw', 'Subject', 'SubjectThread', 'SubjectWords',
        'Location', 'SpamProbability',
    ]),
    ('SPAM_IP_VARIABLE', 'ExpressionVariable', [
        'Ip', 'Value', 'IpReverse', 'Octets', 'IsV4', 'IsV6', 'RemoteIp',
        'RemoteIpPtr', 'HeloDomain', 'AuthenticatedAs', 'Asn', 'Country',
        'IsTls', 'EnvFrom', 'EnvFromLocal', 'EnvFromDomain', 'EnvTo', 'From',
        'FromName', 'FromLocal', 'FromDomain', 'ReplyTo', 'ReplyToName',
        'ReplyToLocal', 'ReplyToDomain', 'To', 'ToName', 'ToLocal', 'ToDomain',
        'Cc', 'CcName', 'CcLocal', 'CcDomain', 'Bcc', 'BccName', 'BccLocal',
        'BccDomain', 'Body', 'BodyText', 'BodyHtml', 'BodyWords', 'BodyRaw',
        'Subject', 'SubjectThread', 'SubjectWords', 'Location',
        'SpamProbability',
    ]),
    ('SPAM_URL_VARIABLE', 'ExpressionVariable', [
        'Url', 'UrlOriginal', 'Value', 'PathQuery', 'Path', 'Query', 'Scheme',
        'Authority', 'Host', 'Sld', 'Port', 'RemoteIp', 'RemoteIpPtr',
        'HeloDomain', 'AuthenticatedAs', 'Asn', 'Country', 'IsTls', 'EnvFrom',
        'EnvFromLocal', 'EnvFromDomain', 'EnvTo', 'From', 'FromName',
        'FromLocal', 'FromDomain', 'ReplyTo', 'ReplyToName', 'ReplyToLocal',
        'ReplyToDomain', 'To', 'ToName', 'ToLocal', 'ToDomain', 'Cc', 'CcName',
        'CcLocal', 'CcDomain', 'Bcc', 'BccName', 'BccLocal', 'BccDomain',
        'Body', 'BodyText', 'BodyHtml', 'BodyWords', 'BodyRaw', 'Subject',
        'SubjectThread', 'SubjectWords', 'Location', 'SpamProbability',
    ]),
    ('MTA_AGGREGATE_CONSTANT', 'ExpressionConstant', [
        'Hourly', 'Daily', 'Weekly', 'Disable',
    ]),
    ('MTA_AUTH_TYPE_CONSTANT', 'ExpressionConstant', [
        'Login', 'Plain', 'Xoauth2', 'Oauthbearer',
    ]),
    ('MTA_PRIORITY_CONSTANT', 'ExpressionConstant', [
        'Mixer', 'Stanag4406', 'Nsep',
    ]),
    ('MTA_VERIFY_CONSTANT', 'ExpressionConstant', [
        'Relaxed', 'Strict', 'Disable',
    ]),
]

# ===========================================================================
# 3. Field declaration order
# ===========================================================================

# schema.json lists every object's properties alphabetically; upstream's
# generator walks them in source declaration order, which decides struct
# field order, the pickle field numbers (on-disk layout), the order of every
# generated statement, and (by first sighting, walking schemas
# alphabetically) the numeric `Property` ids.
#
# Open fields: taken from the reference output (patch-arm order, which also
# lists the non-stored "virtual" fields).
# Enterprise fields inside open schemas: placed in the gaps the reference
# leaves in its pickle field numbers and in its `Property` ids; where a
# schema has several, the 0.16.27 snapshot (commit ad1330f) orders them.
# Enterprise-only schemas: 0.16.27 order, with fields new in 1.0 inserted
# after their predecessor in the schema's form layout; schemas new in 1.0
# (AiModel*, SpamAi*) are ordered to satisfy the `Property` id gaps, then by
# form layout. Confidence per entry is noted in README.md.
#
# The `Property` ids computed from this table match all 937 open ids of the
# reference exactly and fill its 75 gaps exactly.
FIELD_ORDER = {
    'x:AccountPassword': [
        'secret', 'currentSecret', 'otpAuth',
    ],
    'x:AccountSettings': [
        'description', 'locale', 'timeZone', 'encryptionAtRest',
    ],
    'x:AcmeProvider': [  # has Enterprise fields
        'challengeType', 'contact', 'directory', 'eabHmacKey', 'eabKeyId',
        'accountKey', 'accountUri', 'accountHashPrefix', 'issuerDomainNames',
        'caaIdentities', 'renewBefore', 'memberTenantId', 'preferredChain',
        'reuseKey', 'description',
    ],
    'x:AddressBook': [
        'defaultDisplayName', 'defaultHrefName', 'maxVCardSize',
        'maxAddressBooks', 'maxContacts', 'vCardVersion',
        'maxAddressBooksPerCard', 'maxMediaSize',
    ],
    'x:AiModelAnthropic': [  # Enterprise-only schema
        'extraParameters', 'maxOutputTokens', 'reasoning', 'temperature',
        'name', 'model', 'url', 'apiKey', 'httpHeaders', 'allowInvalidCerts',
        'timeout', 'maxConcurrentRequests', 'rateLimit',
    ],
    'x:AiModelGemini': [  # Enterprise-only schema
        'extraParameters', 'logprobs', 'maxOutputTokens', 'reasoning',
        'temperature', 'name', 'model', 'url', 'apiKey', 'httpHeaders',
        'allowInvalidCerts', 'timeout', 'maxConcurrentRequests', 'rateLimit',
    ],
    'x:AiModelOllama': [  # Enterprise-only schema
        'extraParameters', 'keepAlive', 'logprobs', 'maxOutputTokens',
        'reasoning', 'temperature', 'name', 'model', 'url', 'apiKey',
        'httpHeaders', 'allowInvalidCerts', 'timeout', 'maxConcurrentRequests',
        'rateLimit',
    ],
    'x:AiModelOpenAi': [  # Enterprise-only schema
        'extraParameters', 'logprobs', 'maxOutputTokens', 'profile',
        'reasoning', 'temperature', 'name', 'model', 'url', 'apiKey',
        'httpHeaders', 'allowInvalidCerts', 'timeout', 'maxConcurrentRequests',
        'rateLimit',
    ],
    'x:AiModelTypeSafe': [  # Enterprise-only schema
        'name', 'model', 'url', 'apiKey', 'httpHeaders', 'allowInvalidCerts',
        'timeout', 'maxConcurrentRequests', 'rateLimit',
    ],
    'x:Alert': [  # Enterprise-only schema
        'condition', 'emailAlert', 'eventAlert', 'enable',
    ],
    'x:AlertEmailProperties': [  # Enterprise-only schema
        'body', 'fromAddress', 'fromName', 'subject', 'to',
    ],
    'x:AlertEventProperties': [  # Enterprise-only schema
        'eventMessage',
    ],
    'x:AllowedIp': [
        'address', 'reason', 'createdAt', 'expiresAt',
    ],
    'x:ApiKey': [
        'description', 'secret', 'createdAt', 'expiresAt', 'permissions',
        'allowedIps',
    ],
    'x:AppPassword': [
        'description', 'secret', 'createdAt', 'expiresAt', 'permissions',
        'allowedIps',
    ],
    'x:Application': [
        'enable', 'description', 'resourceUrl', 'urlPrefix',
        'autoUpdateInterval', 'unpackDirectory', 'oauthClientId',
    ],
    'x:ArchivedCalendarEvent': [  # Enterprise-only schema
        'title', 'startTime', 'createdAt', 'accountId', 'archivedAt',
        'archivedUntil', 'blobId', 'status',
    ],
    'x:ArchivedContactCard': [  # Enterprise-only schema
        'name', 'createdAt', 'accountId', 'archivedAt', 'archivedUntil',
        'blobId', 'status',
    ],
    'x:ArchivedEmail': [  # Enterprise-only schema
        'from', 'subject', 'receivedAt', 'size', 'accountId', 'archivedAt',
        'archivedUntil', 'blobId', 'status',
    ],
    'x:ArchivedFileNode': [  # Enterprise-only schema
        'name', 'createdAt', 'accountId', 'archivedAt', 'archivedUntil',
        'blobId', 'status',
    ],
    'x:ArchivedSieveScript': [  # Enterprise-only schema
        'name', 'createdAt', 'contents', 'accountId', 'archivedAt',
        'archivedUntil', 'blobId', 'status',
    ],
    'x:ArfExternalReport': [  # has Enterprise fields
        'report', 'from', 'subject', 'to', 'receivedAt', 'expiresAt',
        'memberTenantId',
    ],
    'x:ArfFeedbackReport': [
        'feedbackType', 'arrivalDate', 'authenticationResults', 'incidents',
        'originalEnvelopeId', 'originalMailFrom', 'originalRcptTo',
        'reportedDomains', 'reportedUris', 'reportingMta', 'sourceIp',
        'sourcePort', 'userAgent', 'version', 'authFailure', 'deliveryResult',
        'dkimAdspDns', 'dkimCanonicalizedBody', 'dkimCanonicalizedHeader',
        'dkimDomain', 'dkimIdentity', 'dkimSelector', 'dkimSelectorDns',
        'spfDns', 'identityAlignment', 'message', 'headers',
    ],
    'x:AsnDns': [
        'indexAsn', 'indexAsnName', 'indexCountry', 'separator', 'zoneIpV4',
        'zoneIpV6',
    ],
    'x:AsnResource': [
        'refreshInterval', 'maxSize', 'timeout', 'asnUrls', 'geoUrls',
        'allowInvalidCerts', 'httpAuth', 'httpHeaders',
    ],
    'x:Authentication': [  # has Enterprise fields
        'directoryId', 'defaultUserRoleIds', 'defaultGroupRoleIds',
        'defaultTenantRoleIds', 'defaultAdminRoleIds', 'passwordHashAlgorithm',
        'minPasswordLength', 'maxPasswordLength', 'minPasswordStrength',
        'passwordDefaultExpiry', 'maxAppPasswords', 'maxApiKeys',
    ],
    'x:AzureAuthClientSecret': [
        'tenantId', 'clientId', 'clientSecret',
    ],
    'x:AzureAuthManagedIdentity': [
        'clientId',
    ],
    'x:AzureAuthSasToken': [
        'sasToken',
    ],
    'x:AzureAuthSharedKey': [
        'accountKey',
    ],
    'x:AzureAuthWorkloadIdentity': [
        'tenantId', 'clientId', 'tokenFile',
    ],
    'x:AzureStore': [
        'storageAccount', 'container', 'environment', 'url', 'auth', 'timeout',
        'maxRetries', 'keyPrefix',
    ],
    'x:BlobStoreSwap': [
        'store', 'retention', 'flushChanges', 'flushInterval',
        'maxAccountSize', 'minAccountSize',
    ],
    'x:BlockedIp': [
        'address', 'reason', 'createdAt', 'expiresAt',
    ],
    'x:Bootstrap': [
        'defaultHostname', 'defaultDomain', 'requestTlsCertificate',
        'generateDkimKeys', 'dataStore', 'blobStore', 'searchStore',
        'inMemoryStore', 'directory', 'tracer', 'dnsServer', 'username',
        'secret',
    ],
    'x:Cache': [  # has Enterprise fields
        'accessTokens', 'contacts', 'dnsIpv4', 'dnsIpv6', 'dnsMtaSts', 'dnsMx',
        'dnsPtr', 'spamLookup', 'dnsTlsa', 'dnsTxt', 'events', 'scheduling',
        'files', 'httpAuth', 'messages', 'messagesLarge', 'messagesLargeTtl',
        'groupwareLarge', 'groupwareLargeTtl', 'domains', 'domainNames',
        'domainNamesNegative', 'emailAddresses', 'emailAddressesNegative',
        'accounts', 'roles', 'tenants', 'mailingLists', 'dkimSignatures',
        'negativeTtl', 'directoryRecipients', 'directoryRecipientsTtl', 'swap',
    ],
    'x:Calendar': [
        'defaultDisplayName', 'defaultHrefName', 'maxAttendees',
        'maxRecurrenceExpansions', 'maxICalendarSize', 'maxCalendars',
        'maxEvents', 'maxParticipantIdentities', 'maxEventNotifications',
        'maxCalendarsPerEvent', 'maxExpandedQueryDuration',
        'maxAvailabilityDuration', 'availabilityRateLimit',
        'maxAttachmentsSize',
    ],
    'x:CalendarAlarm': [  # has Enterprise fields
        'allowExternalRcpts', 'enable', 'fromAddress', 'fromName',
        'minTriggerInterval', 'template',
    ],
    'x:CalendarScheduling': [  # has Enterprise fields
        'enable', 'httpRsvpEnable', 'httpRsvpLinkExpiry', 'httpRsvpUrl',
        'autoAddInvitations', 'maxItipSize', 'maxRecipients', 'emailTemplate',
        'httpRsvpTemplate',
    ],
    'x:Certificate': [
        'certificate', 'privateKey', 'subjectAlternativeNames',
        'notValidAfter', 'notValidBefore', 'issuer',
    ],
    'x:CertificateManagementProperties': [
        'acmeProviderId', 'subjectAlternativeNames',
    ],
    'x:ClusterListenerGroupProperties': [
        'listenerIds',
    ],
    'x:ClusterNode': [
        'nodeId', 'hostname', 'lastRenewal', 'status',
    ],
    'x:ClusterRole': [
        'name', 'description', 'tasks', 'listeners',
    ],
    'x:ClusterTaskGroupProperties': [
        'taskTypes',
    ],
    'x:CredentialPermissionsList': [
        'permissions',
    ],
    'x:CronDaily': [
        'hour', 'minute',
    ],
    'x:CronHourly': [
        'minute',
    ],
    'x:CronWeekly': [
        'day', 'hour', 'minute',
    ],
    'x:CustomRoles': [
        'roleIds',
    ],
    'x:DataRetention': [  # has Enterprise fields
        'expungeTrashAfter', 'expungeSubmissionsAfter',
        'expungeShareNotifyAfter', 'expungeSchedulingInboxAfter',
        'expungeSchedule', 'dataCleanupSchedule', 'blobCleanupSchedule',
        'maxChangesHistory', 'archiveDeletedItemsFor',
        'archiveDeletedAccountsFor', 'holdMtaReportsFor', 'holdTracesFor',
        'holdMetricsFor', 'metricsCollectionInterval',
    ],
    'x:DeliveryError': [
        'errorType', 'errorMessage', 'errorCommand', 'responseHostname',
        'responseCode', 'responseEnhanced', 'responseMessage',
    ],
    'x:Dkim1Signature': [  # has Enterprise fields
        'auid', 'canonicalization', 'expire', 'headers', 'privateKey',
        'publicKey', 'report', 'thirdParty', 'thirdPartyHash', 'domainId',
        'memberTenantId', 'selector', 'createdAt', 'nextTransitionAt', 'stage',
    ],
    'x:Dkim2Signature': [  # has Enterprise fields
        'flags', 'instanceHashes', 'privateKey', 'publicKey', 'domainId',
        'memberTenantId', 'selector', 'createdAt', 'nextTransitionAt', 'stage',
    ],
    'x:DkimManagementProperties': [
        'algorithms', 'selectorTemplate', 'rotateAfter', 'retireAfter',
        'deleteAfter',
    ],
    'x:DkimReportSettings': [
        'fromAddress', 'fromName', 'sendFrequency', 'dkimSignDomain',
        'subject',
    ],
    'x:DmarcDkimResult': [
        'domain', 'selector', 'result', 'humanResult',
    ],
    'x:DmarcExtension': [
        'name', 'definition',
    ],
    'x:DmarcExternalReport': [  # has Enterprise fields
        'report', 'from', 'subject', 'to', 'receivedAt', 'expiresAt',
        'memberTenantId',
    ],
    'x:DmarcInternalReport': [
        'rua', 'policyIdentifier', 'report', 'domain', 'createdAt',
        'deliverAt',
    ],
    'x:DmarcPolicyOverrideReason': [
        'overrideType', 'comment',
    ],
    'x:DmarcReport': [
        'version', 'orgName', 'email', 'extraContactInfo', 'reportId',
        'dateRangeStart', 'dateRangeEnd', 'errors', 'policyDomain',
        'policyVersion', 'policyAdkim', 'policyAspf', 'policyDisposition',
        'policySubdomainDisposition', 'policyTestingMode',
        'policyFailureReportingOptions', 'records', 'extensions', 'generator',
        'policyNp', 'policyDiscoveryMethod',
    ],
    'x:DmarcReportRecord': [
        'sourceIp', 'count', 'evaluatedDisposition', 'evaluatedDkim',
        'evaluatedSpf', 'policyOverrideReasons', 'envelopeTo', 'envelopeFrom',
        'headerFrom', 'dkimResults', 'spfResults', 'extensions',
    ],
    'x:DmarcReportSettings': [
        'aggregateContactInfo', 'aggregateFromAddress', 'aggregateFromName',
        'maxAggregateReportSize', 'aggregateOrgName', 'aggregateSendFrequency',
        'aggregateDkimSignDomain', 'failureFromAddress', 'failureFromName',
        'failureSendFrequency', 'failureDkimSignDomain', 'failureSubject',
    ],
    'x:DmarcSpfResult': [
        'domain', 'scope', 'result', 'humanResult',
    ],
    'x:DmarcTroubleshoot': [
        'remoteIp', 'ehloDomain', 'mailFrom', 'rcptTo', 'message',
        'spfEhloDomain', 'spfEhloResult', 'spfMailFromDomain',
        'spfMailFromResult', 'ipRevResult', 'ipRevPtr', 'dkimResults',
        'dkimPass', 'dkim2Result', 'dkim2Pass', 'arcResult', 'dmarcResult',
        'dmarcPass', 'dmarcPolicy', 'elapsed',
    ],
    'x:DmarcTroubleshootDetails': [
        'details',
    ],
    'x:DnsCustomResolver': [
        'protocol', 'address', 'port',
    ],
    'x:DnsManagementProperties': [
        'dnsServerId', 'origin', 'publishRecords',
    ],
    'x:DnsResolverCommon': [
        'attempts', 'maxConcurrentRequests', 'enableEdns',
        'preserveIntermediates', 'timeout', 'tcpOnError',
    ],
    'x:DnsResolverCustom': [
        'servers', 'attempts', 'maxConcurrentRequests', 'enableEdns',
        'preserveIntermediates', 'timeout', 'tcpOnError',
    ],
    'x:DnsResolverTls': [
        'useTls', 'attempts', 'maxConcurrentRequests', 'enableEdns',
        'preserveIntermediates', 'timeout', 'tcpOnError',
    ],
    'x:DnsServerAlidns': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'region', 'sessionToken', 'line',
        'description', 'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerAutodns': [  # has Enterprise fields
        'username', 'password', 'context', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerAzureDns': [  # has Enterprise fields
        'tenantId', 'clientId', 'clientSecret', 'subscriptionId',
        'resourceGroup', 'environment', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerBaiduCloud': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerBluecatV2': [  # has Enterprise fields
        'url', 'username', 'password', 'configName', 'viewName', 'skipDeploy',
        'description', 'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerClouDns': [  # has Enterprise fields
        'authId', 'subAuthId', 'password', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerCloud': [  # has Enterprise fields
        'secret', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerCloudflare': [  # has Enterprise fields
        'secret', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerConstellix': [  # has Enterprise fields
        'apiKeyId', 'secretKey', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerCpanel': [  # has Enterprise fields
        'url', 'username', 'token', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerDnsMadeEasy': [  # has Enterprise fields
        'apiKeyId', 'secret', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerDnsimple': [  # has Enterprise fields
        'token', 'accountIdentifier', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerDomeneshop': [  # has Enterprise fields
        'token', 'secret', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerEasyDns': [  # has Enterprise fields
        'token', 'key', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerEdgeDns': [  # has Enterprise fields
        'host', 'clientToken', 'clientSecret', 'accessToken',
        'accountSwitchKey', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerExoscale': [  # has Enterprise fields
        'apiKeyId', 'secret', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerGlesys': [  # has Enterprise fields
        'username', 'apiKey', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerGodaddy': [  # has Enterprise fields
        'apiKeyId', 'secret', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerGoogleCloudDns': [  # has Enterprise fields
        'serviceAccountJson', 'projectId', 'managedZone', 'privateZone',
        'impersonateServiceAccount', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerHuaweiCloud': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'region', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerHurricane': [  # has Enterprise fields
        'credentials', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerIbmCloud': [  # has Enterprise fields
        'username', 'apiKey', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerInfoblox': [  # has Enterprise fields
        'host', 'port', 'username', 'password', 'wapiVersion', 'dnsView',
        'description', 'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerInwx': [  # has Enterprise fields
        'username', 'password', 'sharedSecret', 'sandbox', 'description',
        'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerJoker': [  # has Enterprise fields
        'auth', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerLightsail': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'sessionToken', 'region', 'domain',
        'description', 'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerLuaDns': [  # has Enterprise fields
        'username', 'token', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerMythicBeasts': [  # has Enterprise fields
        'username', 'password', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerNameDotCom': [  # has Enterprise fields
        'username', 'token', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerNamecheap': [  # has Enterprise fields
        'apiUser', 'apiKey', 'clientIp', 'username', 'description',
        'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerNetcup': [  # has Enterprise fields
        'customerNumber', 'apiKeyId', 'password', 'description',
        'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerNifcloud': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerOracleCloud': [  # has Enterprise fields
        'tenancyOcid', 'userOcid', 'fingerprint', 'privateKeyPem',
        'privateKeyPassword', 'region', 'compartmentOcid', 'description',
        'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerOvh': [  # has Enterprise fields
        'applicationKey', 'applicationSecret', 'consumerKey', 'ovhEndpoint',
        'description', 'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerPlesk': [  # has Enterprise fields
        'url', 'apiKey', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerPorkbun': [  # has Enterprise fields
        'apiKeyId', 'secret', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerPowerDns': [  # has Enterprise fields
        'apiKey', 'url', 'serverId', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerRoute53': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'sessionToken', 'region', 'hostedZoneId',
        'privateZoneOnly', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerSpaceship': [  # has Enterprise fields
        'apiKeyId', 'secret', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerTencentCloud': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'region', 'sessionToken', 'description',
        'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerTransip': [  # has Enterprise fields
        'username', 'privateKeyPem', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerTsig': [  # has Enterprise fields
        'host', 'port', 'keyName', 'key', 'protocol', 'tsigAlgorithm',
        'description', 'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerUltraDns': [  # has Enterprise fields
        'username', 'password', 'url', 'description', 'memberTenantId',
        'timeout', 'ttl', 'pollInterval', 'propagationTimeout',
        'propagationDelay',
    ],
    'x:DnsServerVercel': [  # has Enterprise fields
        'token', 'teamId', 'description', 'memberTenantId', 'timeout', 'ttl',
        'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerVolcengine': [  # has Enterprise fields
        'accessKeyId', 'secretKey', 'region', 'host', 'scheme', 'description',
        'memberTenantId', 'timeout', 'ttl', 'pollInterval',
        'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerWebSupport': [  # has Enterprise fields
        'apiKeyId', 'secret', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:DnsServerYandexCloud': [  # has Enterprise fields
        'apiKey', 'folderId', 'description', 'memberTenantId', 'timeout',
        'ttl', 'pollInterval', 'propagationTimeout', 'propagationDelay',
    ],
    'x:Domain': [  # has Enterprise fields
        'name', 'aliases', 'enable', 'createdAt', 'description', 'logo',
        'certificateManagement', 'dkimManagement', 'dnsManagement',
        'dnsZoneFile', 'memberTenantId', 'directoryId', 'catchAllAddress',
        'subAddressing', 'allowRelaying', 'reportAddressUri',
        'allowScimProvisioning',
    ],
    'x:DsnReportSettings': [
        'fromAddress', 'fromName', 'dkimSignDomain',
    ],
    'x:ElasticSearchStore': [
        'url', 'numReplicas', 'numShards', 'includeSource', 'timeout',
        'allowInvalidCerts', 'httpAuth', 'httpHeaders',
    ],
    'x:Email': [  # has Enterprise fields
        'maxAttachmentSize', 'maxMessageSize', 'maxMailboxDepth',
        'maxMailboxNameLength', 'encryptOnAppend', 'encryptAtRest',
        'compressionAlgorithm', 'defaultFolders', 'maxMessages',
        'maxSubmissions', 'maxIdentities', 'maxMailboxes',
        'maxMaskedAddresses', 'maxPublicKeys', 'maxMailboxesPerEmail',
        'maxFlagsPerEmail', 'maxFlagLength', 'maxHeaderSize', 'maxHeaderCount',
    ],
    'x:EmailAlias': [
        'enable', 'name', 'domainId', 'description',
    ],
    'x:EmailFolder': [
        'name', 'create', 'subscribe', 'aliases',
    ],
    'x:EncryptionSettings': [
        'publicKey', 'encryptOnAppend', 'allowSpamTraining',
    ],
    'x:Enterprise': [  # Enterprise-only schema
        'apiKey', 'licenseKey', 'logo',
    ],
    'x:EventTracingLevel': [
        'event', 'level',
    ],
    'x:Expression': [
        'match', 'else',
    ],
    'x:ExpressionMatch': [
        'if', 'then',
    ],
    'x:FileStorage': [
        'maxSize', 'maxFiles', 'maxFolders',
    ],
    'x:FileSystemStore': [
        'path', 'depth',
    ],
    'x:FoundationDbStore': [
        'clusterFile', 'datacenterId', 'machineId', 'transactionRetryDelay',
        'transactionRetryLimit', 'transactionTimeout',
    ],
    'x:FtrlParameters': [
        'alpha', 'beta', 'numFeatures', 'l1Ratio', 'l2Ratio',
    ],
    'x:GroupAccount': [  # has Enterprise fields
        'name', 'domainId', 'emailAddress', 'description', 'createdAt',
        'memberTenantId', 'roles', 'quotas', 'usedDiskQuota', 'permissions',
        'aliases', 'locale', 'timeZone', 'externalId',
    ],
    'x:Http': [
        'rateLimitAuthenticated', 'rateLimitAnonymous', 'allowedEndpoints',
        'enableHsts', 'usePermissiveCors', 'responseHeaders', 'clientIpSource',
        'forwardedHops', 'redirectRoot',
    ],
    'x:HttpAuthBasic': [
        'username', 'secret',
    ],
    'x:HttpAuthBearer': [
        'bearerToken',
    ],
    'x:HttpForm': [
        'deliverTo', 'defaultFromAddress', 'fieldEmail', 'enable',
        'fieldHoneyPot', 'maxSize', 'defaultName', 'fieldName', 'rateLimit',
        'defaultSubject', 'fieldSubject', 'validateDomain',
    ],
    'x:HttpLookup': [
        'namespace', 'enable', 'format', 'isGzipped', 'maxEntries',
        'maxEntrySize', 'maxSize', 'refreshInterval', 'retry', 'url',
        'timeout', 'allowInvalidCerts', 'httpAuth', 'httpHeaders',
    ],
    'x:HttpLookupCsv': [
        'indexKey', 'indexValue', 'separator', 'skipFirst',
    ],
    'x:HurricaneCredential': [
        'zone', 'secret',
    ],
    'x:Imap': [
        'allowPlainTextAuth', 'maxAuthFailures', 'maxConcurrentConnections',
        'rateLimit', 'maxRequestSize', 'anonymousTimeout',
        'authenticatedTimeout', 'idleTimeout', 'maxMessagesPerCommand',
        'minUidBatchSize', 'maxUidBatches', 'maxMessagesPerSave',
    ],
    'x:IndexQueueStatus': [
        'index', 'partition', 'queuedUpdates', 'queuedDeletions', 'status',
    ],
    'x:IndexStatusFailed': [
        'reason', 'nextRetry',
    ],
    'x:Jmap': [
        'parseLimitEvent', 'parseLimitContact', 'parseLimitEmail',
        'maxChangesResults', 'maxGetResults', 'maxQueryResults',
        'maxMethodCalls', 'maxConcurrentRequests', 'maxRequestSize',
        'maxSetObjects', 'maxSnippetResults', 'maxConcurrentUploads',
        'maxUploadSize', 'maxUploadCount', 'uploadQuota', 'uploadTtl',
        'eventSourceThrottle', 'pushAttemptWait', 'maxPushAttempts',
        'pushRetryWait', 'pushThrottle', 'pushRequestTimeout',
        'pushVerifyTimeout', 'pushShardsTotal', 'websocketHeartbeat',
        'websocketThrottle', 'websocketTimeout', 'maxSubscriptions',
        'webPushKey', 'webPushContact', 'maxPushSize',
    ],
    'x:JokerAuthApiKey': [
        'apiKey',
    ],
    'x:JokerAuthUsernamePassword': [
        'username', 'password',
    ],
    'x:KafkaCoordinator': [
        'hosts', 'groupId', 'messageTimeout', 'sessionTimeout', 'useTls',
        'allowInvalidCerts',
    ],
    'x:LdapDirectory': [  # has Enterprise fields
        'description', 'url', 'urlFailover', 'timeout', 'allowInvalidCerts',
        'useTls', 'baseDn', 'bindDn', 'bindSecret', 'bindAuthentication',
        'filterLogin', 'filterRecipient', 'filterMemberOf', 'attrClass',
        'attrDescription', 'attrEmail', 'attrEmailAlias', 'attrMemberOf',
        'attrSecret', 'attrSecretChanged', 'groupClass', 'poolMaxConnections',
        'poolTimeoutCreate', 'poolTimeoutRecycle', 'poolTimeoutWait',
        'memberTenantId',
    ],
    'x:LocalFileSwap': [
        'path', 'flushChanges', 'flushInterval', 'maxAccountSize',
        'minAccountSize',
    ],
    'x:Log': [
        'timestamp', 'level', 'event', 'details',
    ],
    'x:MailExchanger': [
        'hostname', 'priority',
    ],
    'x:MailingList': [  # has Enterprise fields
        'name', 'domainId', 'emailAddress', 'description', 'aliases',
        'memberTenantId', 'recipients',
    ],
    'x:MaskedEmail': [  # Enterprise-only schema
        'enable', 'accountId', 'email', 'description', 'forDomain',
        'createdAt', 'createdBy', 'emailPrefix', 'emailDomain', 'expiresAt',
        'url',
    ],
    'x:MeilisearchStore': [
        'url', 'pollInterval', 'maxPolls', 'failOnTimeout', 'timeout',
        'allowInvalidCerts', 'httpAuth', 'httpHeaders',
    ],
    'x:MemoryLookupKey': [
        'namespace', 'key', 'isGlobPattern',
    ],
    'x:MemoryLookupKeyValue': [
        'namespace', 'key', 'value', 'isGlobPattern',
    ],
    'x:Metadata': [
        'dataTypes', 'vendorNamespaces', 'privateMetadata', 'maxDepth',
        'maxEntrySize', 'maxSize', 'maxPrivateSize', 'maxEntries',
        'maxQueryScan', 'imapServerComment', 'imapServerAdmin',
    ],
    'x:MetricCount': [  # Enterprise-only schema
        'count', 'metric', 'nodeId', 'timestamp',
    ],
    'x:MetricSum': [  # Enterprise-only schema
        'count', 'sum', 'metric', 'nodeId', 'timestamp',
    ],
    'x:Metrics': [
        'openTelemetry', 'prometheus', 'metrics', 'metricsPolicy',
    ],
    'x:MetricsOtelGrpc': [
        'url', 'interval', 'timeout',
    ],
    'x:MetricsOtelHttp': [
        'url', 'interval', 'timeout', 'allowInvalidCerts', 'httpAuth',
        'httpHeaders',
    ],
    'x:MetricsPrometheusProperties': [
        'authSecret', 'authUsername',
    ],
    'x:MtaConnectionIpHost': [
        'ehloHostname', 'localIp',
    ],
    'x:MtaConnectionStrategy': [
        'name', 'description', 'ehloHostname', 'localIps', 'connectTimeout',
        'dataTimeout', 'ehloTimeout', 'greetingTimeout', 'mailFromTimeout',
        'rcptToTimeout',
    ],
    'x:MtaDeliveryExpirationAttempts': [
        'maxAttempts',
    ],
    'x:MtaDeliveryExpirationTtl': [
        'expire',
    ],
    'x:MtaDeliverySchedule': [
        'name', 'description', 'expiry', 'notify', 'queueId', 'retry',
    ],
    'x:MtaDeliveryScheduleInterval': [
        'duration',
    ],
    'x:MtaDeliveryScheduleIntervals': [
        'intervals',
    ],
    'x:MtaExtensions': [
        'chunking', 'deliverBy', 'dsn', 'expn', 'futureRelease', 'mtPriority',
        'noSoliciting', 'pipelining', 'requireTls', 'vrfy',
    ],
    'x:MtaHook': [
        'enable', 'maxResponseSize', 'tempFailOnError', 'stages', 'url',
        'timeout', 'allowInvalidCerts', 'httpAuth', 'httpHeaders',
    ],
    'x:MtaInboundSession': [
        'maxDuration', 'idleTimeout', 'transferLimit',
    ],
    'x:MtaInboundThrottle': [
        'enable', 'description', 'key', 'match', 'rate',
    ],
    'x:MtaMilter': [
        'allowInvalidCerts', 'enable', 'host', 'maxResponseSize',
        'tempFailOnError', 'protocolVersion', 'port', 'stages',
        'commandTimeout', 'connectTimeout', 'dataTimeout', 'useTls',
        'flagsAction', 'flagsProtocol',
    ],
    'x:MtaOutboundStrategy': [
        'connection', 'route', 'schedule', 'tls',
    ],
    'x:MtaOutboundThrottle': [
        'enable', 'description', 'key', 'match', 'rate',
    ],
    'x:MtaQueueQuota': [
        'enable', 'description', 'key', 'match', 'messages', 'size',
    ],
    'x:MtaRouteCommon': [
        'name', 'description',
    ],
    'x:MtaRouteMx': [
        'ipLookupStrategy', 'maxMultihomed', 'maxMxHosts', 'name',
        'description',
    ],
    'x:MtaRouteRelay': [
        'host', 'authSecret', 'authUsername', 'port', 'protocol',
        'allowInvalidCerts', 'implicitTls', 'name', 'description',
    ],
    'x:MtaStageAuth': [
        'maxFailures', 'waitOnFail', 'saslMechanisms', 'mustMatchSender',
        'require',
    ],
    'x:MtaStageConnect': [
        'smtpGreeting', 'hostname', 'script',
    ],
    'x:MtaStageData': [
        'addAuthResultsHeader', 'addDateHeader', 'addDeliveredToHeader',
        'addMessageIdHeader', 'addReceivedHeader', 'addReceivedSpfHeader',
        'addReturnPathHeader', 'maxMessages', 'maxReceivedHeaders',
        'maxMessageSize', 'script', 'enableSpamFilter', 'dkimSignDomain',
    ],
    'x:MtaStageEhlo': [
        'rejectNonFqdn', 'require', 'script',
    ],
    'x:MtaStageMail': [
        'isSenderAllowed', 'rewrite', 'script',
    ],
    'x:MtaStageRcpt': [
        'maxFailures', 'waitOnFail', 'maxRecipients', 'allowRelaying',
        'rewrite', 'script',
    ],
    'x:MtaSts': [
        'maxAge', 'mode', 'mxHosts',
    ],
    'x:MtaTlsStrategy': [
        'name', 'allowInvalidCerts', 'dane', 'description', 'mtaSts',
        'startTls', 'mtaStsTimeout', 'tlsTimeout',
    ],
    'x:MtaVirtualQueue': [
        'name', 'description', 'threadsPerNode',
    ],
    'x:MySqlSettings': [  # Enterprise-only schema
        'host', 'port', 'database', 'authUsername', 'authSecret',
    ],
    'x:MySqlStore': [  # has Enterprise fields
        'idleTimeout', 'useTls', 'allowInvalidCerts', 'maxAllowedPacket',
        'poolMaxConnections', 'poolMinConnections', 'readReplicas', 'host',
        'port', 'database', 'authUsername', 'authSecret',
    ],
    'x:NatsCoordinator': [
        'hosts', 'maxReconnects', 'connectTimeout', 'requestTimeout',
        'pingInterval', 'clientCapacity', 'readBufferCapacity',
        'subscriptionCapacity', 'noEcho', 'useTls', 'allowInvalidCerts',
        'authSecret', 'authUsername', 'credentials',
    ],
    'x:NetworkListener': [
        'name', 'bind', 'protocol', 'overrideProxyTrustedNetworks',
        'socketBacklog', 'socketNoDelay', 'socketReceiveBufferSize',
        'socketReuseAddress', 'socketReusePort', 'socketSendBufferSize',
        'socketTosV4', 'socketTtl', 'useTls', 'tlsDisableCipherSuites',
        'tlsDisableProtocols', 'tlsIgnoreClientOrder', 'implicitTls',
        'tlsTimeout', 'maxConnections',
    ],
    'x:OAuthClient': [  # has Enterprise fields
        'clientId', 'description', 'contacts', 'secret', 'createdAt',
        'expiresAt', 'memberTenantId', 'redirectUris',
        'postLogoutRedirectUris', 'logo', 'firstParty', 'scopes', 'grantTypes',
    ],
    'x:OAuthGrant': [
        'accountId', 'clientId', 'clientName', 'clientKind', 'scopes',
        'remoteIp', 'createdAt', 'lastUsedAt', 'generation', 'pending',
    ],
    'x:OidcDirectory': [  # has Enterprise fields
        'description', 'issuerUrl', 'allowInvalidCerts', 'claimUsername',
        'usernameDomain', 'claimName', 'claimGroups', 'memberTenantId',
        'acceptedAudiences', 'opaqueTokenValidation', 'introspectionClientId',
        'introspectionClientSecret', 'introspectionAuthMethod',
        'unscopedTokens', 'skipAudienceValidation', 'allowIdTokenClaims',
        'lenientIssuerMatch',
    ],
    'x:OidcProvider': [
        'authCodeExpiry', 'refreshTokenExpiry', 'accessTokenExpiry',
        'userCodeExpiry', 'idTokenExpiry', 'encryptionKey',
        'signatureAlgorithm', 'signatureKey', 'clientMetadataDocuments',
        # inbuxa: kept from 0.16 (anonymous registration stays gated)
        'anonymousClientRegistration',
    ],
    'x:OtpAuth': [
        'otpCode', 'otpUrl',
    ],
    'x:PasswordCredential': [
        'credentialId', 'secret', 'otpUrl', 'expiresAt', 'allowedIps',
    ],
    'x:PermissionsList': [
        'enabledPermissions', 'disabledPermissions',
    ],
    'x:PostgreSqlSettings': [  # Enterprise-only schema
        'host', 'port', 'database', 'authUsername', 'authSecret', 'options',
    ],
    'x:PostgreSqlStore': [  # has Enterprise fields
        'connectTimeout', 'useTls', 'allowInvalidCerts', 'poolMaxConnections',
        'poolRecyclingMethod', 'readReplicas', 'host', 'port', 'database',
        'authUsername', 'authSecret', 'options',
    ],
    'x:PublicKey': [
        'accountId', 'key', 'description', 'createdAt', 'expiresAt',
        'emailAddresses',
    ],
    'x:PublicStringValue': [
        'value',
    ],
    'x:PublicTextValue': [
        'value',
    ],
    'x:QueueExpiryAttempts': [
        'expiresAttempts',
    ],
    'x:QueueExpiryTtl': [
        'expiresAt',
    ],
    'x:QueuedMessage': [
        'createdAt', 'nextRetry', 'nextNotify', 'blobId', 'returnPath',
        'recipients', 'receivedFromIp', 'receivedViaPort', 'flags', 'envId',
        'priority', 'size',
    ],
    'x:QueuedRecipient': [
        'retryCount', 'retryDue', 'notifyCount', 'notifyDue', 'expires',
        'queueName', 'status', 'flags', 'orcpt',
    ],
    'x:Rate': [
        'count', 'period',
    ],
    'x:RedisClusterStore': [
        'urls', 'connectTimeout', 'allowInvalidCerts', 'authUsername',
        'authSecret', 'maxRetryWait', 'minRetryWait', 'maxRetries',
        'readFromReplicas', 'protocolVersion', 'poolMaxConnections',
        'poolTimeoutCreate', 'poolTimeoutWait', 'poolTimeoutRecycle',
    ],
    'x:RedisSentinelStore': [
        'urls', 'serviceName', 'connectTimeout', 'allowInvalidCerts',
        'authUsername', 'authSecret', 'sentinelUsername', 'sentinelSecret',
        'protocolVersion', 'poolMaxConnections', 'poolTimeoutCreate',
        'poolTimeoutWait', 'poolTimeoutRecycle',
    ],
    'x:RedisStore': [
        'url', 'connectTimeout', 'allowInvalidCerts', 'poolMaxConnections',
        'poolTimeoutCreate', 'poolTimeoutWait', 'poolTimeoutRecycle',
    ],
    'x:RedisSwap': [
        'store', 'chunkSize', 'retention', 'flushChanges', 'flushInterval',
        'maxAccountSize', 'minAccountSize',
    ],
    'x:ReloadSettingsResult': [
        'warnings',
    ],
    'x:ReportSettings': [
        'inboundReportAddresses', 'inboundReportForwarding',
        'outboundReportDomain', 'outboundReportSubmitter',
        'maxInboundReportSize',
    ],
    'x:RocksDbStore': [
        'path', 'blobSize', 'bufferSize', 'poolWorkers', 'cacheSize',
    ],
    'x:Role': [  # has Enterprise fields
        'description', 'memberTenantId', 'roleIds', 'enabledPermissions',
        'disabledPermissions',
    ],
    'x:S3Store': [
        'region', 'bucket', 'accessKeyId', 'secretKey', 'sessionToken',
        'profile', 'timeout', 'maxRetries', 'keyPrefix', 'allowInvalidCerts',
        'verifyAfterWrite',
    ],
    'x:S3StoreCustomRegion': [
        'url', 'region',
    ],
    'x:Search': [  # has Enterprise fields
        'indexBatchSize', 'defaultLanguage', 'supportedLanguages',
        'indexCalendar', 'indexCalendarFields', 'indexContacts',
        'indexContactFields', 'indexEmail', 'indexEmailFields',
        'indexTelemetry', 'maxConcurrentIndexTasks', 'indexFiles',
        'maxExtractDocumentSize', 'maxExtractTextSize',
        'maxExtractDecompressedSize', 'maxExtractPartSize', 'maxExtractParts',
        'maxExtractArchiveEntries', 'maxExtractPdfObjects',
        'maxExtractRtfDepth',
    ],
    'x:SecondaryCredential': [
        'credentialId', 'description', 'secret', 'createdAt', 'expiresAt',
        'permissions', 'allowedIps',
    ],
    'x:SecretKeyEnvironmentVariable': [
        'variableName',
    ],
    'x:SecretKeyFile': [
        'filePath',
    ],
    'x:SecretKeyValue': [
        'secret',
    ],
    'x:SecretTextValue': [
        'secret',
    ],
    'x:Security': [
        'abuseBanRate', 'abuseBanPeriod', 'authBanRate', 'authBanPeriod',
        'loiterBanRate', 'loiterBanPeriod', 'scanBanPaths', 'scanBanRate',
        'scanBanPeriod',
    ],
    'x:SenderAuth': [
        'dkimStrict', 'dkimVerify', 'spfEhloVerify', 'spfFromVerify',
        'arcVerify', 'dmarcVerify', 'reverseIpVerify',
    ],
    'x:ServerResponse': [
        'responseHostname', 'responseCode', 'responseEnhanced',
        'responseMessage',
    ],
    'x:Service': [
        'hostname', 'cleartext',
    ],
    'x:ShardedBlobStore': [  # Enterprise-only schema
        'stores',
    ],
    'x:ShardedInMemoryStore': [  # Enterprise-only schema
        'stores',
    ],
    'x:Sharing': [
        'allowDirectoryQueries', 'maxShares',
    ],
    'x:SieveSystemInterpreter': [
        'defaultFromAddress', 'defaultFromName', 'messageIdHostname',
        'noCapabilityCheck', 'defaultReturnPath', 'dkimSignDomain',
        'maxCpuCycles', 'maxNestedIncludes', 'maxOutMessages',
        'maxReceivedHeaders', 'maxRedirects', 'maxVarSize',
    ],
    'x:SieveSystemScript': [
        'name', 'description', 'isActive', 'contents',
    ],
    'x:SieveUserInterpreter': [
        'defaultExpiryDuplicate', 'defaultExpiryVacation',
        'disableCapabilities', 'allowedNotifyUris', 'protectedHeaders',
        'defaultSubject', 'defaultSubjectPrefix', 'maxCpuCycles',
        'maxHeaderSize', 'maxIncludes', 'maxLocalVars', 'maxMatchVars',
        'maxScriptNameLength', 'maxNestedBlocks', 'maxNestedForEvery',
        'maxNestedIncludes', 'maxNestedTests', 'maxOutMessages',
        'maxReceivedHeaders', 'maxRedirects', 'maxScriptSize',
        'maxStringLength', 'maxVarNameLength', 'maxVarSize', 'maxScripts',
        'dkimSignDomain',
    ],
    'x:SieveUserScript': [
        'name', 'description', 'isActive', 'contents',
    ],
    'x:SpamAiCategory': [  # Enterprise-only schema
        'name', 'description', 'includes',
    ],
    'x:SpamAiLearnProperties': [  # Enterprise-only schema
        'minProbability', 'sampleRate',
    ],
    'x:SpamAiProperties': [  # Enterprise-only schema
        'mode', 'condition', 'tiers', 'instructions', 'categories', 'signals',
        'explanation', 'bucketHigh', 'bucketMedium', 'uncertainBelow',
        'verbalHigh', 'verbalMedium', 'verbalLow', 'addHeader',
        'maxInputChars', 'maxLinks', 'maxAttachments', 'trimQuotes',
        'includeAuth', 'includeLinks', 'includeAttachments', 'deadline',
        'breakerThreshold', 'breakerCooldown', 'learn', 'webSearch',
    ],
    'x:SpamAiSignal': [  # Enterprise-only schema
        'name', 'question',
    ],
    'x:SpamAiTier': [  # Enterprise-only schema
        'modelId', 'escalateBelow', 'escalateOn',
    ],
    'x:SpamClassifier': [
        'model', 'learnHamFromCard', 'learnSpamFromRblHits',
        'learnSpamFromTraps', 'holdSamplesFor', 'minHamSamples',
        'minSpamSamples', 'reservoirCapacity', 'trainInterval',
        'learnHamFromReply',
    ],
    'x:SpamClassifierFtrlCcfh': [
        'indicatorParameters', 'parameters', 'featureL2Normalize',
        'featureLogScale',
    ],
    'x:SpamClassifierFtrlFh': [
        'parameters', 'featureL2Normalize', 'featureLogScale',
    ],
    'x:SpamClassify': [  # has Enterprise fields
        'message', 'remoteIp', 'ehloDomain', 'authenticatedAs', 'isTls',
        'mailFrom', 'mailFromParameters', 'rcptTo', 'score', 'tags', 'aiGate',
        'aiVerdict', 'aiFacts', 'result',
    ],
    'x:SpamClassifyTag': [
        'score', 'disposition',
    ],
    'x:SpamDnsblServerAny': [
        'tag', 'zone', 'name', 'description', 'enable',
    ],
    'x:SpamDnsblServerBody': [
        'tag', 'zone', 'name', 'description', 'enable',
    ],
    'x:SpamDnsblServerDomain': [
        'tag', 'zone', 'name', 'description', 'enable',
    ],
    'x:SpamDnsblServerEmail': [
        'tag', 'zone', 'name', 'description', 'enable',
    ],
    'x:SpamDnsblServerHeader': [
        'tag', 'zone', 'name', 'description', 'enable',
    ],
    'x:SpamDnsblServerIp': [
        'tag', 'zone', 'name', 'description', 'enable',
    ],
    'x:SpamDnsblServerUrl': [
        'tag', 'zone', 'name', 'description', 'enable',
    ],
    'x:SpamDnsblSettings': [
        'domainLimit', 'emailLimit', 'ipLimit', 'urlLimit',
    ],
    'x:SpamFileExtension': [
        'extension', 'isArchive', 'isBad', 'isNz', 'contentTypes',
    ],
    'x:SpamPyzor': [
        'blockCount', 'enable', 'host', 'port', 'ratio', 'timeout',
        'allowCount',
    ],
    'x:SpamRuleAny': [
        'condition', 'name', 'description', 'enable', 'priority',
    ],
    'x:SpamRuleBody': [
        'condition', 'name', 'description', 'enable', 'priority',
    ],
    'x:SpamRuleDomain': [
        'condition', 'name', 'description', 'enable', 'priority',
    ],
    'x:SpamRuleEmail': [
        'condition', 'name', 'description', 'enable', 'priority',
    ],
    'x:SpamRuleHeader': [
        'condition', 'name', 'description', 'enable', 'priority',
    ],
    'x:SpamRuleIp': [
        'condition', 'name', 'description', 'enable', 'priority',
    ],
    'x:SpamRuleUrl': [
        'condition', 'name', 'description', 'enable', 'priority',
    ],
    'x:SpamSettings': [
        'trustContacts', 'enable', 'greylistFor', 'scoreDiscard',
        'scoreReject', 'scoreSpam', 'trustReplies', 'spamFilterRulesUrl',
        'maxBodyText', 'maxAttachmentText', 'maxMessageText',
        'maxRedirectUrls', 'redirectTimeout', 'redirectCacheTtl',
    ],
    'x:SpamTagAction': [
        'tag',
    ],
    'x:SpamTagScore': [
        'tag', 'score',
    ],
    'x:SpamTrainingSample': [
        'from', 'subject', 'blobId', 'isSpam', 'accountId', 'expiresAt',
        'deleteAfterUse',
    ],
    'x:SpfReportSettings': [
        'fromAddress', 'fromName', 'sendFrequency', 'dkimSignDomain',
        'subject',
    ],
    'x:SqlDirectory': [  # has Enterprise fields
        'description', 'store', 'columnEmail', 'columnSecret', 'columnClass',
        'columnDescription', 'queryLogin', 'queryRecipient', 'queryMemberOf',
        'queryEmailAliases', 'memberTenantId',
    ],
    'x:SqliteStore': [
        'path', 'poolWorkers', 'poolMaxConnections',
    ],
    'x:StoreLookup': [
        'namespace', 'store',
    ],
    'x:SubAddressingCustom': [
        'customRule',
    ],
    'x:SystemSettings': [
        'defaultHostname', 'defaultDomainId', 'defaultCertificateId',
        'maxConnections', 'maxBufferedMemory', 'proxyTrustedNetworks',
        'mailExchangers', 'services', 'providerInfo', 'includeSecrets',
    ],
    'x:TaskAccountMaintenance': [
        'accountId', 'maintenanceType', 'status', 'due',
    ],
    'x:TaskCalendarAlarmEmail': [
        'alarmId', 'eventId', 'eventStart', 'eventEnd', 'eventStartTz',
        'eventEndTz', 'targetAccountId', 'recurrenceId', 'accountId',
        'documentId', 'status', 'due',
    ],
    'x:TaskCalendarAlarmNotification': [
        'alarmId', 'eventId', 'recurrenceId', 'targetAccountId', 'accountId',
        'documentId', 'status', 'due',
    ],
    'x:TaskCalendarItipContents': [
        'from', 'to', 'isFromOrganizer', 'iCalendarData', 'summary',
    ],
    'x:TaskCalendarItipMessage': [
        'messages', 'accountId', 'documentId', 'status', 'due',
    ],
    'x:TaskDestroyAccount': [
        'accountId', 'accountName', 'accountDomainId', 'accountType',
        'memberGroupIds', 'status', 'due',
    ],
    'x:TaskDmarcReport': [
        'reportId', 'status', 'due',
    ],
    'x:TaskDnsManagement': [
        'updateRecords', 'onSuccessRenewCertificate', 'domainId', 'status',
        'due',
    ],
    'x:TaskDomainManagement': [
        'domainId', 'status', 'due',
    ],
    'x:TaskManager': [
        'strategy', 'alertAfter',
    ],
    'x:TaskMergeThreads': [
        'accountId', 'threadName', 'messageIds', 'status', 'due',
    ],
    'x:TaskReportWindow': [
        'windowEnd', 'status', 'due',
    ],
    'x:TaskRestoreArchivedItem': [  # Enterprise-only schema
        'blobId', 'archivedItemType', 'createdAt', 'archivedUntil',
        'accountId', 'status', 'due',
    ],
    'x:TaskRetryStrategyBackoff': [
        'factor', 'initialDelay', 'maxDelay', 'jitter',
    ],
    'x:TaskRetryStrategyFixed': [
        'delay',
    ],
    'x:TaskShareRevokeCleanup': [
        'objectType', 'accountId', 'documentId', 'status', 'due',
    ],
    'x:TaskSpamFilterMaintenance': [
        'maintenanceType', 'status', 'due',
    ],
    'x:TaskStatusFailed': [
        'createdAt', 'failedAt', 'failedAttemptNumber', 'failureReason',
    ],
    'x:TaskStatusPending': [
        'createdAt', 'due',
    ],
    'x:TaskStatusRetry': [
        'createdAt', 'due', 'attemptNumber', 'firstFailedAt', 'failureReason',
    ],
    'x:TaskStoreMaintenance': [
        'maintenanceType', 'shardIndex', 'status', 'due',
    ],
    'x:TaskTenantMaintenance': [  # Enterprise-only schema
        'tenantId', 'maintenanceType', 'status', 'due',
    ],
    'x:TaskTlsReport': [
        'reportId', 'status', 'due',
    ],
    'x:Tenant': [  # Enterprise-only schema
        'name', 'createdAt', 'usedDiskQuota', 'logo', 'roles', 'permissions',
        'quotas',
    ],
    'x:TlsExternalReport': [  # has Enterprise fields
        'report', 'from', 'subject', 'to', 'receivedAt', 'expiresAt',
        'memberTenantId',
    ],
    'x:TlsFailureDetails': [
        'resultType', 'sendingMtaIp', 'receivingMxHostname', 'receivingMxHelo',
        'receivingIp', 'failedSessionCount', 'additionalInformation',
        'failureReasonCode',
    ],
    'x:TlsInternalReport': [
        'policyIdentifiers', 'mailRua', 'httpRua', 'report', 'domain',
        'createdAt', 'deliverAt',
    ],
    'x:TlsReport': [
        'organizationName', 'contactInfo', 'reportId', 'dateRangeStart',
        'dateRangeEnd', 'policies',
    ],
    'x:TlsReportPolicy': [
        'policyType', 'policyStrings', 'policyDomain', 'mxHosts',
        'totalSuccessfulSessions', 'totalFailedSessions', 'failureDetails',
    ],
    'x:TlsReportSettings': [
        'contactInfo', 'fromAddress', 'fromName', 'maxReportSize', 'orgName',
        'sendFrequency', 'dkimSignDomain',
    ],
    'x:Trace': [  # Enterprise-only schema
        'events', 'timestamp', 'from', 'to', 'size',
    ],
    'x:TraceEvent': [  # Enterprise-only schema
        'event', 'timestamp', 'keyValues',
    ],
    'x:TraceKeyValue': [  # Enterprise-only schema
        'key', 'value',
    ],
    'x:TraceValueBoolean': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueDuration': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueEvent': [  # Enterprise-only schema
        'event', 'value',
    ],
    'x:TraceValueFloat': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueInteger': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueIpAddr': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueList': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueString': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueUTCDateTime': [  # Enterprise-only schema
        'value',
    ],
    'x:TraceValueUnsignedInt': [  # Enterprise-only schema
        'value',
    ],
    'x:TracerCommon': [
        'enable', 'level', 'lossy', 'events', 'eventsPolicy',
    ],
    'x:TracerLog': [
        'path', 'prefix', 'rotate', 'ansi', 'multiline', 'enable', 'level',
        'lossy', 'events', 'eventsPolicy',
    ],
    'x:TracerOtelGrpc': [
        'url', 'enableLogExporter', 'enableSpanExporter', 'throttle',
        'timeout', 'httpAuth', 'httpHeaders', 'enable', 'level', 'lossy',
        'events', 'eventsPolicy',
    ],
    'x:TracerOtelHttp': [
        'url', 'allowInvalidCerts', 'enableLogExporter', 'enableSpanExporter',
        'throttle', 'timeout', 'httpAuth', 'httpHeaders', 'enable', 'level',
        'lossy', 'events', 'eventsPolicy',
    ],
    'x:TracerStdout': [
        'buffered', 'ansi', 'multiline', 'enable', 'level', 'lossy', 'events',
        'eventsPolicy',
    ],
    'x:UserAccount': [  # has Enterprise fields
        'name', 'domainId', 'emailAddress', 'credentials', 'createdAt',
        'memberGroupIds', 'memberTenantId', 'roles', 'permissions', 'quotas',
        'usedDiskQuota', 'aliases', 'externalId', 'description', 'locale',
        'timeZone', 'encryptionAtRest',
    ],
    'x:WebDav': [
        'enableAssistedDiscovery', 'maxLockTimeout', 'maxLocks',
        'maxLivePropertySize', 'maxRequestSize', 'maxResults',
    ],
    'x:WebHook': [
        'enable', 'level', 'lossy', 'signatureKey', 'throttle', 'discardAfter',
        'url', 'timeout', 'allowInvalidCerts', 'httpAuth', 'httpHeaders',
        'events', 'eventsPolicy',
    ],
    'x:ZenohCoordinator': [
        'config',
    ],
}

# Declared fields that are not stored in the struct: computed or write-only
# values. They take part in `Property` id assignment and are accepted (and
# passed through) by patching, but have no struct field, pickle slot or
# default.
VIRTUAL_FIELDS = {
    'x:AcmeProvider': ['eabHmacKey', 'eabKeyId'],
    'x:Bootstrap': ['secret', 'username'],
    'x:Dkim1Signature': ['publicKey'],
    'x:Dkim2Signature': ['publicKey'],
    'x:Domain': ['dnsZoneFile'],
    'x:GroupAccount': ['emailAddress', 'usedDiskQuota'],
    'x:UserAccount': ['emailAddress', 'usedDiskQuota'],
    'x:MailingList': ['emailAddress'],
    'x:Tenant': ['usedDiskQuota'],  # Enterprise; by analogy with the accounts
    # Enterprise; computed in 0.16.27 (not a struct field there either).
    **{f'x:Archived{n}': ['status'] for n in (
        'CalendarEvent', 'ContactCard', 'Email', 'FileNode', 'SieveScript')},
    # Every Task* schema's `due` lives in the task queue key, not the value.
    **{f'x:Task{n}': ['due'] for n in (
        'AccountMaintenance', 'CalendarAlarmEmail', 'CalendarAlarmNotification',
        'CalendarItipMessage', 'DestroyAccount', 'DmarcReport', 'DnsManagement',
        'DomainManagement', 'MergeThreads', 'ReportWindow', 'ShareRevokeCleanup',
        'SpamFilterMaintenance', 'StoreMaintenance', 'TlsReport',
        'RestoreArchivedItem', 'TenantMaintenance')},
}

# ===========================================================================
# 4. Rust types the schema does not imply
# ===========================================================================

# (schema, field) -> Rust type (before Option<> for nullable fields).
RUST_TYPE_OVERRIDES = {
    # Declared as plain strings in the schema, stored as document ids.
    ('x:PasswordCredential', 'credentialId'): 'Id',
    ('x:SecondaryCredential', 'credentialId'): 'Id',
    ('x:TaskCalendarAlarmEmail', 'documentId'): 'Id',
    ('x:TaskCalendarAlarmNotification', 'documentId'): 'Id',
    ('x:TaskCalendarItipMessage', 'documentId'): 'Id',
    ('x:TaskShareRevokeCleanup', 'documentId'): 'Id',
    # A set of strings in the schema, a set of numbers in the code.
    ('x:TlsInternalReport', 'policyIdentifiers'): 'Map<u64>',
}

# ===========================================================================
# 5. Default values
# ===========================================================================

# The fork's renames (tools/fork/renames.py) changed these string literals in
# the generated code but not in schema.json.
STRING_LITERAL_RENAMES = {
    '/var/log/stalwart/': '/var/log/inbuxa/',
    'stalwart.log': 'inbuxa.log',
}

# Default string sets in declared order (schema.json sorts set keys; enum
# sets are put back in enum order by the generator, string sets cannot be).
SET_DEFAULT_ORDER = {
    ('x:Dkim1Signature', 'headers'): ['From', 'To', 'Date', 'Subject', 'Message-ID'],
    ('x:Security', 'scanBanPaths'): [
        '*.php*', '*.cgi*', '*.asp*', '*/wp-*', '*/php*', '*/cgi-bin*', '*xmlrpc*',
        '*../*', '*/..*', '*joomla*', '*wordpress*', '*drupal*'],
    ('x:SieveUserInterpreter', 'protectedHeaders'): [
        'Original-Subject', 'Original-From', 'Received', 'Auto-Submitted'],
}

# Size defaults written with a u64 suffix (the rest are bare integers). The
# schema gives the same number either way; upstream's source evidently spells
# them differently. Open fields from the reference, the rest from 0.16.27.
SIZE_DEFAULT_SUFFIX = {
    ('x:AddressBook', 'maxVCardSize'),
    ('x:ArchivedEmail', 'size'),
    ('x:Email', 'maxAttachmentSize'),
    ('x:Email', 'maxHeaderSize'),
    ('x:Email', 'maxMessageSize'),
    ('x:HttpLookup', 'maxEntrySize'),
    ('x:Jmap', 'maxPushSize'),
    ('x:Jmap', 'maxRequestSize'),
    ('x:Jmap', 'maxUploadSize'),
    ('x:Metadata', 'maxEntrySize'),
    ('x:Metadata', 'maxPrivateSize'),
    ('x:Metadata', 'maxSize'),
    ('x:MtaHook', 'maxResponseSize'),
    ('x:MtaMilter', 'maxResponseSize'),
    ('x:ReportSettings', 'maxInboundReportSize'),
    ('x:RocksDbStore', 'blobSize'),
    ('x:RocksDbStore', 'bufferSize'),
    ('x:RocksDbStore', 'cacheSize'),
    ('x:Search', 'maxExtractDecompressedSize'),
    ('x:Search', 'maxExtractDocumentSize'),
    ('x:Search', 'maxExtractPartSize'),
    ('x:Search', 'maxExtractTextSize'),
    ('x:SpamSettings', 'maxAttachmentText'),
    ('x:SpamSettings', 'maxBodyText'),
    ('x:SpamSettings', 'maxMessageText'),
    ('x:WebDav', 'maxLivePropertySize'),
}

# ===========================================================================
# 6. Indexes
# ===========================================================================

# Index entries each field contributes, besides the two derived ones (a
# foreign key for every objectId field, and recursing into nested types that
# have indexes). Ops: ('text', P), ('search', P), ('unique', P),
# ('unique_global', P), ('composite', P, 'docid'|'field', other_field).
# Open fields: from the reference; Enterprise fields and schemas: from the
# 0.16.27 snapshot (fields new in 1.0 are assumed to have none).
INDEX_OPS = {
    'x:AccountSettings': {
        'description': [('text', 'Text')],
    },
    'x:AcmeProvider': {
        'contact': [('text', 'Text')],
        'directory': [('text', 'Text')],
        'description': [('text', 'Text')],
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:AllowedIp': {
        'address': [('unique', 'Address')],
    },
    'x:ArchivedCalendarEvent': {
        'accountId': [('search', 'AccountId')],
    },
    'x:ArchivedContactCard': {
        'accountId': [('search', 'AccountId')],
    },
    'x:ArchivedEmail': {
        'accountId': [('search', 'AccountId')],
    },
    'x:ArchivedFileNode': {
        'accountId': [('search', 'AccountId')],
    },
    'x:ArchivedSieveScript': {
        'accountId': [('search', 'AccountId')],
    },
    'x:BlockedIp': {
        'address': [('unique', 'Address')],
    },
    'x:Certificate': {
        'subjectAlternativeNames': [('text', 'SubjectAlternativeNames')],
    },
    'x:ClusterRole': {
        'name': [('unique', 'Name')],
    },
    'x:Dkim1Signature': {
        'domainId': [('search', 'DomainId')],
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:Dkim2Signature': {
        'domainId': [('search', 'DomainId')],
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerAlidns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerAutodns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerAzureDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerBaiduCloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerBluecatV2': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerClouDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerCloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerCloudflare': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerConstellix': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerCpanel': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerDnsMadeEasy': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerDnsimple': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerDomeneshop': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerEasyDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerEdgeDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerExoscale': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerGlesys': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerGodaddy': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerGoogleCloudDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerHuaweiCloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerHurricane': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerIbmCloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerInfoblox': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerInwx': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerJoker': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerLightsail': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerLuaDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerMythicBeasts': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerNameDotCom': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerNamecheap': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerNetcup': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerNifcloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerOracleCloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerOvh': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerPlesk': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerPorkbun': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerPowerDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerRoute53': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerSpaceship': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerTencentCloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerTransip': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerTsig': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerUltraDns': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerVercel': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerVolcengine': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerWebSupport': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:DnsServerYandexCloud': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:Domain': {
        'name': [('unique', 'Name'), ('text', 'Text')],
        'aliases': [('unique', 'Aliases'), ('text', 'Text')],
        'description': [('text', 'Text')],
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:EmailAlias': {
        'name': [('composite', 'Email', 'docid', 'domain_id'), ('text', 'Text')],
    },
    'x:EventTracingLevel': {
        'event': [('unique', 'Event')],
    },
    'x:GroupAccount': {
        'name': [('composite', 'Email', 'docid', 'domain_id'), ('text', 'Text'), ('search', 'Name')],
        'domainId': [('search', 'DomainId')],
        'description': [('text', 'Text')],
        'memberTenantId': [('search', 'MemberTenantId')],
        'externalId': [('search', 'ExternalId')],
    },
    'x:HttpLookup': {
        'namespace': [('unique_global', 'Namespace')],
    },
    'x:LdapDirectory': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:MailingList': {
        'name': [('composite', 'Email', 'docid', 'domain_id'), ('text', 'Text')],
        'description': [('text', 'Text')],
        'recipients': [('text', 'Text')],
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:MaskedEmail': {
        'accountId': [('search', 'AccountId')],
    },
    'x:MemoryLookupKey': {
        'namespace': [('composite', 'Namespace', 'field', 'key'), ('search', 'Namespace')],
    },
    'x:MemoryLookupKeyValue': {
        'namespace': [('composite', 'Namespace', 'field', 'key'), ('search', 'Namespace')],
    },
    'x:MtaConnectionStrategy': {
        'name': [('unique', 'Name')],
    },
    'x:MtaDeliverySchedule': {
        'name': [('unique', 'Name')],
    },
    'x:MtaRouteCommon': {
        'name': [('unique', 'Name')],
    },
    'x:MtaRouteMx': {
        'name': [('unique', 'Name')],
    },
    'x:MtaRouteRelay': {
        'name': [('unique', 'Name')],
    },
    'x:MtaTlsStrategy': {
        'name': [('unique', 'Name')],
    },
    'x:MtaVirtualQueue': {
        'name': [('unique', 'Name')],
    },
    'x:NetworkListener': {
        'name': [('unique', 'Name')],
    },
    'x:OAuthClient': {
        'clientId': [('unique', 'ClientId')],
        'description': [('text', 'Text')],
        'contacts': [('text', 'Text')],
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:OAuthGrant': {
        'accountId': [('search', 'AccountId')],
    },
    'x:OidcDirectory': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:PublicKey': {
        'accountId': [('search', 'AccountId')],
    },
    'x:Role': {
        'description': [('text', 'Description')],
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:SieveSystemScript': {
        'name': [('unique', 'Name')],
    },
    'x:SieveUserScript': {
        'name': [('unique', 'Name')],
    },
    'x:SpamDnsblServerAny': {
        'name': [('unique', 'Name')],
    },
    'x:SpamDnsblServerBody': {
        'name': [('unique', 'Name')],
    },
    'x:SpamDnsblServerDomain': {
        'name': [('unique', 'Name')],
    },
    'x:SpamDnsblServerEmail': {
        'name': [('unique', 'Name')],
    },
    'x:SpamDnsblServerHeader': {
        'name': [('unique', 'Name')],
    },
    'x:SpamDnsblServerIp': {
        'name': [('unique', 'Name')],
    },
    'x:SpamDnsblServerUrl': {
        'name': [('unique', 'Name')],
    },
    'x:SpamFileExtension': {
        'extension': [('unique', 'Extension')],
    },
    'x:SpamRuleAny': {
        'name': [('unique', 'Name')],
    },
    'x:SpamRuleBody': {
        'name': [('unique', 'Name')],
    },
    'x:SpamRuleDomain': {
        'name': [('unique', 'Name')],
    },
    'x:SpamRuleEmail': {
        'name': [('unique', 'Name')],
    },
    'x:SpamRuleHeader': {
        'name': [('unique', 'Name')],
    },
    'x:SpamRuleIp': {
        'name': [('unique', 'Name')],
    },
    'x:SpamRuleUrl': {
        'name': [('unique', 'Name')],
    },
    'x:SpamTagAction': {
        'tag': [('unique', 'Tag')],
    },
    'x:SpamTagScore': {
        'tag': [('unique', 'Tag')],
    },
    'x:SpamTrainingSample': {
        'accountId': [('search', 'AccountId')],
    },
    'x:SqlDirectory': {
        'memberTenantId': [('search', 'MemberTenantId')],
    },
    'x:StoreLookup': {
        'namespace': [('unique_global', 'Namespace')],
    },
    'x:Tenant': {
        'name': [('text', 'Text')],
    },
    'x:UserAccount': {
        'name': [('composite', 'Email', 'docid', 'domain_id'), ('text', 'Text'), ('search', 'Name')],
        'domainId': [('search', 'DomainId')],
        'memberGroupIds': [('search', 'MemberGroupIds')],
        'description': [('text', 'Text')],
        'memberTenantId': [('search', 'MemberTenantId')],
        'externalId': [('search', 'ExternalId')],
    },
}

# Registry objects whose multi-variant index also records the variant
# (`i.typ(n)` and an `@type` index schema).
TYPE_INDEXED_OBJECTS = {'x:Account'}


# ===========================================================================
# 7. Object flags (ObjectImpl::FLAGS)
# ===========================================================================
# Derived: OBJ_SINGLETON (schema type), OBJ_FILTER_TENANT (some variant has
# memberTenantId), OBJ_FILTER_ACCOUNT (every variant has accountId), and
# OBJ_NO_GET/CREATE/UPDATE/DESTROY/QUERY (the Permission enum lacks
# sys<Object><Op>). Not derivable:

# Objects with sequential numeric ids.
SEQ_ID_OBJECTS = {
    'x:Account', 'x:Domain', 'x:MailingList', 'x:OAuthClient', 'x:OAuthGrant',
    'x:Role',
    'x:Tenant',  # Enterprise; from the 0.16.27 snapshot
}

# Objects that are not stored in the registry (computed, or kept elsewhere).
# Types reachable only from these are not pickled.
NOT_STORED_OBJECTS = {
    'x:AccountPassword', 'x:AccountSettings', 'x:Action', 'x:ApiKey',
    'x:AppPassword', 'x:Bootstrap', 'x:ClusterNode', 'x:DataStore',
    'x:IndexQueueStatus', 'x:Log', 'x:QueuedMessage',
}


# ===========================================================================
# 8. Validation, patching and expression contexts
# ===========================================================================
# STRING_VALIDATORS, VALIDATE_MAX_FIRST, VALIDATE_IF_NOT_EMPTY,
# EXPRESSION_CONTEXTS and SIZE_DEFAULT_SUFFIX (section 5) were produced by
# tools/extract_tables.py: open fields from the v1.0.0 reference, Enterprise
# fields from the 0.16.27 snapshot. Enterprise fields new in 1.0 are in
# neither, so the derived rules apply to them.

# String validators applied when patching a field. Derived default: an
# emailAddress field gets [Email] (unless server-set); everything else none.
# Formats do not predict the rest (plain strings get Trim, Domain, Hostname,
# EmailLocalPart, Uppercase+RemoveSpaces... or nothing).
# (schema, field) -> [StringValidator variants]
STRING_VALIDATORS = {
    ('x:AcmeProvider', 'description'): ['Trim'],
    ('x:AcmeProvider', 'directory'): ['Trim'],
    ('x:AcmeProvider', 'preferredChain'): ['Trim'],
    ('x:AddressBook', 'defaultDisplayName'): ['Trim'],
    ('x:AddressBook', 'defaultHrefName'): ['Trim'],
    ('x:AllowedIp', 'address'): ['Trim'],
    ('x:AllowedIp', 'reason'): ['Trim'],
    ('x:Application', 'description'): ['Trim'],
    ('x:Application', 'oauthClientId'): ['Trim'],
    ('x:Application', 'resourceUrl'): ['Trim'],
    ('x:Application', 'unpackDirectory'): ['Trim'],
    ('x:Application', 'urlPrefix'): ['Trim'],
    ('x:ArfFeedbackReport', 'reportedDomains'): ['Domain'],
    ('x:AsnDns', 'separator'): ['Trim'],
    ('x:AsnDns', 'zoneIpV4'): ['Trim'],
    ('x:AsnDns', 'zoneIpV6'): ['Trim'],
    ('x:AsnResource', 'asnUrls'): ['Trim'],
    ('x:AsnResource', 'geoUrls'): ['Trim'],
    ('x:AsnResource', 'httpHeaders'): ['Trim'],
    ('x:AzureAuthClientSecret', 'clientId'): ['Trim'],
    ('x:AzureAuthClientSecret', 'tenantId'): ['Trim'],
    ('x:AzureAuthManagedIdentity', 'clientId'): ['Trim'],
    ('x:AzureAuthWorkloadIdentity', 'clientId'): ['Trim'],
    ('x:AzureAuthWorkloadIdentity', 'tenantId'): ['Trim'],
    ('x:AzureAuthWorkloadIdentity', 'tokenFile'): ['Trim'],
    ('x:AzureStore', 'container'): ['Trim'],
    ('x:AzureStore', 'keyPrefix'): ['Trim'],
    ('x:AzureStore', 'storageAccount'): ['Trim'],
    ('x:AzureStore', 'url'): ['Trim'],
    ('x:Calendar', 'defaultDisplayName'): ['Trim'],
    ('x:Calendar', 'defaultHrefName'): ['Trim'],
    ('x:CalendarAlarm', 'fromName'): ['Trim'],
    ('x:CalendarScheduling', 'httpRsvpUrl'): ['Trim'],
    ('x:CertificateManagementProperties', 'subjectAlternativeNames'): ['Trim'],
    ('x:Dkim1Signature', 'auid'): ['Trim'],
    ('x:Dkim1Signature', 'headers'): ['Trim'],
    ('x:Dkim1Signature', 'selector'): ['Trim'],
    ('x:Dkim1Signature', 'thirdParty'): ['Trim'],
    ('x:Dkim2Signature', 'selector'): ['Trim'],
    ('x:DkimManagementProperties', 'selectorTemplate'): ['Trim'],
    ('x:DmarcDkimResult', 'domain'): ['Domain'],
    ('x:DmarcInternalReport', 'domain'): ['Domain'],
    ('x:DmarcSpfResult', 'domain'): ['Domain'],
    ('x:DnsCustomResolver', 'address'): ['Trim'],
    ('x:DnsManagementProperties', 'origin'): ['Trim'],
    ('x:DnsServerAlidns', 'accessKeyId'): ['Trim'],
    ('x:DnsServerAlidns', 'description'): ['Trim'],
    ('x:DnsServerAlidns', 'line'): ['Trim'],
    ('x:DnsServerAlidns', 'region'): ['Trim'],
    ('x:DnsServerAutodns', 'description'): ['Trim'],
    ('x:DnsServerAutodns', 'username'): ['Trim'],
    ('x:DnsServerAzureDns', 'clientId'): ['Trim'],
    ('x:DnsServerAzureDns', 'description'): ['Trim'],
    ('x:DnsServerAzureDns', 'resourceGroup'): ['Trim'],
    ('x:DnsServerAzureDns', 'subscriptionId'): ['Trim'],
    ('x:DnsServerAzureDns', 'tenantId'): ['Trim'],
    ('x:DnsServerBaiduCloud', 'accessKeyId'): ['Trim'],
    ('x:DnsServerBaiduCloud', 'description'): ['Trim'],
    ('x:DnsServerBluecatV2', 'configName'): ['Trim'],
    ('x:DnsServerBluecatV2', 'description'): ['Trim'],
    ('x:DnsServerBluecatV2', 'url'): ['Trim'],
    ('x:DnsServerBluecatV2', 'username'): ['Trim'],
    ('x:DnsServerBluecatV2', 'viewName'): ['Trim'],
    ('x:DnsServerClouDns', 'authId'): ['Trim'],
    ('x:DnsServerClouDns', 'description'): ['Trim'],
    ('x:DnsServerClouDns', 'subAuthId'): ['Trim'],
    ('x:DnsServerCloud', 'description'): ['Trim'],
    ('x:DnsServerCloudflare', 'description'): ['Trim'],
    ('x:DnsServerConstellix', 'apiKeyId'): ['Trim'],
    ('x:DnsServerConstellix', 'description'): ['Trim'],
    ('x:DnsServerCpanel', 'description'): ['Trim'],
    ('x:DnsServerCpanel', 'url'): ['Trim'],
    ('x:DnsServerCpanel', 'username'): ['Trim'],
    ('x:DnsServerDnsMadeEasy', 'apiKeyId'): ['Trim'],
    ('x:DnsServerDnsMadeEasy', 'description'): ['Trim'],
    ('x:DnsServerDnsimple', 'accountIdentifier'): ['Trim'],
    ('x:DnsServerDnsimple', 'description'): ['Trim'],
    ('x:DnsServerDomeneshop', 'description'): ['Trim'],
    ('x:DnsServerDomeneshop', 'token'): ['Trim'],
    ('x:DnsServerEasyDns', 'description'): ['Trim'],
    ('x:DnsServerEasyDns', 'token'): ['Trim'],
    ('x:DnsServerEdgeDns', 'accountSwitchKey'): ['Trim'],
    ('x:DnsServerEdgeDns', 'clientToken'): ['Trim'],
    ('x:DnsServerEdgeDns', 'description'): ['Trim'],
    ('x:DnsServerEdgeDns', 'host'): ['Trim'],
    ('x:DnsServerExoscale', 'apiKeyId'): ['Trim'],
    ('x:DnsServerExoscale', 'description'): ['Trim'],
    ('x:DnsServerGlesys', 'description'): ['Trim'],
    ('x:DnsServerGlesys', 'username'): ['Trim'],
    ('x:DnsServerGodaddy', 'apiKeyId'): ['Trim'],
    ('x:DnsServerGodaddy', 'description'): ['Trim'],
    ('x:DnsServerGoogleCloudDns', 'description'): ['Trim'],
    ('x:DnsServerGoogleCloudDns', 'impersonateServiceAccount'): ['Trim'],
    ('x:DnsServerGoogleCloudDns', 'managedZone'): ['Trim'],
    ('x:DnsServerGoogleCloudDns', 'projectId'): ['Trim'],
    ('x:DnsServerHuaweiCloud', 'accessKeyId'): ['Trim'],
    ('x:DnsServerHuaweiCloud', 'description'): ['Trim'],
    ('x:DnsServerHuaweiCloud', 'region'): ['Trim'],
    ('x:DnsServerHurricane', 'description'): ['Trim'],
    ('x:DnsServerIbmCloud', 'description'): ['Trim'],
    ('x:DnsServerIbmCloud', 'username'): ['Trim'],
    ('x:DnsServerInfoblox', 'description'): ['Trim'],
    ('x:DnsServerInfoblox', 'dnsView'): ['Trim'],
    ('x:DnsServerInfoblox', 'host'): ['Trim'],
    ('x:DnsServerInfoblox', 'username'): ['Trim'],
    ('x:DnsServerInfoblox', 'wapiVersion'): ['Trim'],
    ('x:DnsServerInwx', 'description'): ['Trim'],
    ('x:DnsServerInwx', 'username'): ['Trim'],
    ('x:DnsServerJoker', 'description'): ['Trim'],
    ('x:DnsServerLightsail', 'accessKeyId'): ['Trim'],
    ('x:DnsServerLightsail', 'description'): ['Trim'],
    ('x:DnsServerLightsail', 'domain'): ['Trim'],
    ('x:DnsServerLightsail', 'region'): ['Trim'],
    ('x:DnsServerLuaDns', 'description'): ['Trim'],
    ('x:DnsServerLuaDns', 'username'): ['Trim'],
    ('x:DnsServerMythicBeasts', 'description'): ['Trim'],
    ('x:DnsServerMythicBeasts', 'username'): ['Trim'],
    ('x:DnsServerNameDotCom', 'description'): ['Trim'],
    ('x:DnsServerNameDotCom', 'username'): ['Trim'],
    ('x:DnsServerNamecheap', 'apiUser'): ['Trim'],
    ('x:DnsServerNamecheap', 'clientIp'): ['Trim'],
    ('x:DnsServerNamecheap', 'description'): ['Trim'],
    ('x:DnsServerNamecheap', 'username'): ['Trim'],
    ('x:DnsServerNetcup', 'apiKeyId'): ['Trim'],
    ('x:DnsServerNetcup', 'customerNumber'): ['Trim'],
    ('x:DnsServerNetcup', 'description'): ['Trim'],
    ('x:DnsServerNifcloud', 'accessKeyId'): ['Trim'],
    ('x:DnsServerNifcloud', 'description'): ['Trim'],
    ('x:DnsServerOracleCloud', 'compartmentOcid'): ['Trim'],
    ('x:DnsServerOracleCloud', 'description'): ['Trim'],
    ('x:DnsServerOracleCloud', 'fingerprint'): ['Trim'],
    ('x:DnsServerOracleCloud', 'region'): ['Trim'],
    ('x:DnsServerOracleCloud', 'tenancyOcid'): ['Trim'],
    ('x:DnsServerOracleCloud', 'userOcid'): ['Trim'],
    ('x:DnsServerOvh', 'applicationKey'): ['Trim'],
    ('x:DnsServerOvh', 'description'): ['Trim'],
    ('x:DnsServerPlesk', 'description'): ['Trim'],
    ('x:DnsServerPlesk', 'url'): ['Trim'],
    ('x:DnsServerPorkbun', 'apiKeyId'): ['Trim'],
    ('x:DnsServerPorkbun', 'description'): ['Trim'],
    ('x:DnsServerPowerDns', 'description'): ['Trim'],
    ('x:DnsServerPowerDns', 'serverId'): ['Trim'],
    ('x:DnsServerPowerDns', 'url'): ['Trim'],
    ('x:DnsServerRoute53', 'accessKeyId'): ['Trim'],
    ('x:DnsServerRoute53', 'description'): ['Trim'],
    ('x:DnsServerRoute53', 'hostedZoneId'): ['Trim'],
    ('x:DnsServerRoute53', 'region'): ['Trim'],
    ('x:DnsServerSpaceship', 'apiKeyId'): ['Trim'],
    ('x:DnsServerSpaceship', 'description'): ['Trim'],
    ('x:DnsServerTencentCloud', 'accessKeyId'): ['Trim'],
    ('x:DnsServerTencentCloud', 'description'): ['Trim'],
    ('x:DnsServerTencentCloud', 'region'): ['Trim'],
    ('x:DnsServerTransip', 'description'): ['Trim'],
    ('x:DnsServerTransip', 'username'): ['Trim'],
    ('x:DnsServerTsig', 'description'): ['Trim'],
    ('x:DnsServerTsig', 'host'): ['Trim'],
    ('x:DnsServerTsig', 'keyName'): ['Trim'],
    ('x:DnsServerUltraDns', 'description'): ['Trim'],
    ('x:DnsServerUltraDns', 'url'): ['Trim'],
    ('x:DnsServerUltraDns', 'username'): ['Trim'],
    ('x:DnsServerVercel', 'description'): ['Trim'],
    ('x:DnsServerVercel', 'teamId'): ['Trim'],
    ('x:DnsServerVolcengine', 'accessKeyId'): ['Trim'],
    ('x:DnsServerVolcengine', 'description'): ['Trim'],
    ('x:DnsServerVolcengine', 'host'): ['Trim'],
    ('x:DnsServerVolcengine', 'region'): ['Trim'],
    ('x:DnsServerVolcengine', 'scheme'): ['Trim'],
    ('x:DnsServerWebSupport', 'apiKeyId'): ['Trim'],
    ('x:DnsServerWebSupport', 'description'): ['Trim'],
    ('x:DnsServerYandexCloud', 'description'): ['Trim'],
    ('x:DnsServerYandexCloud', 'folderId'): ['Trim'],
    ('x:Domain', 'aliases'): ['Domain'],
    ('x:Domain', 'name'): ['Domain'],
    ('x:Domain', 'reportAddressUri'): ['Trim'],
    ('x:ElasticSearchStore', 'httpHeaders'): ['Trim'],
    ('x:ElasticSearchStore', 'url'): ['Trim'],
    ('x:EmailAlias', 'name'): ['EmailLocalPart'],
    ('x:EmailFolder', 'aliases'): ['Trim'],
    ('x:EmailFolder', 'name'): ['Trim'],
    ('x:FileSystemStore', 'path'): ['Trim'],
    ('x:FoundationDbStore', 'clusterFile'): ['Trim'],
    ('x:FoundationDbStore', 'datacenterId'): ['Trim'],
    ('x:FoundationDbStore', 'machineId'): ['Trim'],
    ('x:GroupAccount', 'name'): ['EmailLocalPart'],
    ('x:Http', 'redirectRoot'): ['Trim'],
    ('x:Http', 'responseHeaders'): ['Trim'],
    ('x:HttpAuthBasic', 'username'): ['Trim'],
    ('x:HttpForm', 'defaultFromAddress'): ['Trim'],
    ('x:HttpForm', 'defaultName'): ['Trim'],
    ('x:HttpForm', 'defaultSubject'): ['Trim'],
    ('x:HttpForm', 'fieldEmail'): ['Trim'],
    ('x:HttpForm', 'fieldHoneyPot'): ['Trim'],
    ('x:HttpForm', 'fieldName'): ['Trim'],
    ('x:HttpForm', 'fieldSubject'): ['Trim'],
    ('x:HttpLookup', 'httpHeaders'): ['Trim'],
    ('x:HttpLookup', 'namespace'): ['Trim'],
    ('x:HttpLookup', 'url'): ['Trim'],
    ('x:HttpLookupCsv', 'separator'): ['Trim'],
    ('x:HurricaneCredential', 'zone'): ['Domain', 'Trim'],
    ('x:Jmap', 'webPushContact'): ['Trim'],
    ('x:JokerAuthUsernamePassword', 'username'): ['Trim'],
    ('x:KafkaCoordinator', 'groupId'): ['Trim'],
    ('x:LdapDirectory', 'attrClass'): ['Trim'],
    ('x:LdapDirectory', 'attrDescription'): ['Trim'],
    ('x:LdapDirectory', 'attrEmail'): ['Trim'],
    ('x:LdapDirectory', 'attrEmailAlias'): ['Trim'],
    ('x:LdapDirectory', 'attrMemberOf'): ['Trim'],
    ('x:LdapDirectory', 'attrSecret'): ['Trim'],
    ('x:LdapDirectory', 'attrSecretChanged'): ['Trim'],
    ('x:LdapDirectory', 'baseDn'): ['Trim'],
    ('x:LdapDirectory', 'bindDn'): ['Trim'],
    ('x:LdapDirectory', 'description'): ['Trim'],
    ('x:LdapDirectory', 'filterLogin'): ['Trim'],
    ('x:LdapDirectory', 'filterMemberOf'): ['Trim'],
    ('x:LdapDirectory', 'filterRecipient'): ['Trim'],
    ('x:LdapDirectory', 'groupClass'): ['Trim'],
    ('x:LdapDirectory', 'url'): ['Trim'],
    ('x:LocalFileSwap', 'path'): ['Trim'],
    ('x:MailExchanger', 'hostname'): ['Hostname'],
    ('x:MailingList', 'name'): ['EmailLocalPart'],
    ('x:MeilisearchStore', 'httpHeaders'): ['Trim'],
    ('x:MeilisearchStore', 'url'): ['Trim'],
    ('x:Metadata', 'imapServerAdmin'): ['Trim'],
    ('x:MetricsOtelGrpc', 'url'): ['Trim'],
    ('x:MetricsOtelHttp', 'httpHeaders'): ['Trim'],
    ('x:MetricsOtelHttp', 'url'): ['Trim'],
    ('x:MetricsPrometheusProperties', 'authUsername'): ['Trim'],
    ('x:MtaConnectionIpHost', 'ehloHostname'): ['Hostname'],
    ('x:MtaConnectionStrategy', 'ehloHostname'): ['Hostname'],
    ('x:MtaHook', 'httpHeaders'): ['Trim'],
    ('x:MtaHook', 'url'): ['Trim'],
    ('x:MtaMilter', 'host'): ['Trim'],
    ('x:MtaRouteRelay', 'host'): ['Trim'],
    ('x:MtaSts', 'mxHosts'): ['Trim'],
    ('x:MtaVirtualQueue', 'name'): ['Trim'],
    ('x:MySqlSettings', 'authUsername'): ['Trim'],
    ('x:MySqlSettings', 'database'): ['Trim'],
    ('x:MySqlSettings', 'host'): ['Trim'],
    ('x:MySqlStore', 'authUsername'): ['Trim'],
    ('x:MySqlStore', 'database'): ['Trim'],
    ('x:MySqlStore', 'host'): ['Trim'],
    ('x:NatsCoordinator', 'authUsername'): ['Trim'],
    ('x:NetworkListener', 'bind'): ['Trim'],
    ('x:NetworkListener', 'overrideProxyTrustedNetworks'): ['Trim'],
    ('x:OAuthClient', 'clientId'): ['Trim'],
    ('x:OidcDirectory', 'acceptedAudiences'): ['Trim'],
    ('x:OidcDirectory', 'claimGroups'): ['Trim'],
    ('x:OidcDirectory', 'claimName'): ['Trim'],
    ('x:OidcDirectory', 'claimUsername'): ['Trim'],
    ('x:OidcDirectory', 'description'): ['Trim'],
    ('x:OidcDirectory', 'issuerUrl'): ['Trim'],
    ('x:OidcDirectory', 'introspectionClientId'): ['Trim'],
    ('x:PostgreSqlSettings', 'authUsername'): ['Trim'],
    ('x:PostgreSqlSettings', 'database'): ['Trim'],
    ('x:PostgreSqlSettings', 'host'): ['Trim'],
    ('x:PostgreSqlSettings', 'options'): ['Trim'],
    ('x:PostgreSqlStore', 'authUsername'): ['Trim'],
    ('x:PostgreSqlStore', 'database'): ['Trim'],
    ('x:PostgreSqlStore', 'host'): ['Trim'],
    ('x:PostgreSqlStore', 'options'): ['Trim'],
    ('x:PublicKey', 'key'): ['Trim'],
    ('x:PublicStringValue', 'value'): ['Trim'],
    ('x:RedisClusterStore', 'authUsername'): ['Trim'],
    ('x:RedisClusterStore', 'urls'): ['Trim'],
    ('x:RedisSentinelStore', 'authUsername'): ['Trim'],
    ('x:RedisSentinelStore', 'sentinelUsername'): ['Trim'],
    ('x:RedisSentinelStore', 'serviceName'): ['Trim'],
    ('x:RedisSentinelStore', 'urls'): ['Trim'],
    ('x:RedisStore', 'url'): ['Trim'],
    ('x:ReportSettings', 'inboundReportAddresses'): ['Trim'],
    ('x:ReportSettings', 'outboundReportDomain'): ['Domain'],
    ('x:RocksDbStore', 'path'): ['Trim'],
    ('x:S3Store', 'bucket'): ['Trim'],
    ('x:S3Store', 'keyPrefix'): ['Trim'],
    ('x:S3Store', 'profile'): ['Trim'],
    ('x:S3StoreCustomRegion', 'region'): ['Trim'],
    ('x:S3StoreCustomRegion', 'url'): ['Trim'],
    ('x:Security', 'scanBanPaths'): ['Trim'],
    ('x:Service', 'hostname'): ['Hostname'],
    ('x:SieveSystemInterpreter', 'messageIdHostname'): ['Trim'],
    ('x:SieveSystemScript', 'contents'): ['Trim'],
    ('x:SieveSystemScript', 'description'): ['Trim'],
    ('x:SieveSystemScript', 'name'): ['Trim'],
    ('x:SieveUserInterpreter', 'allowedNotifyUris'): ['Trim'],
    ('x:SieveUserInterpreter', 'defaultSubject'): ['Trim'],
    ('x:SieveUserInterpreter', 'protectedHeaders'): ['Trim'],
    ('x:SieveUserScript', 'contents'): ['Trim'],
    ('x:SieveUserScript', 'description'): ['Trim'],
    ('x:SieveUserScript', 'name'): ['Trim'],
    ('x:SpamDnsblServerAny', 'name'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamDnsblServerBody', 'name'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamDnsblServerDomain', 'name'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamDnsblServerEmail', 'name'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamDnsblServerHeader', 'name'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamDnsblServerIp', 'name'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamDnsblServerUrl', 'name'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamFileExtension', 'contentTypes'): ['Trim'],
    ('x:SpamFileExtension', 'extension'): ['RemoveSpaces', 'Lowercase'],
    ('x:SpamPyzor', 'host'): ['Trim'],
    ('x:SpamRuleAny', 'name'): ['Uppercase', 'RemoveSpaces'],
    ('x:SpamRuleBody', 'name'): ['Uppercase', 'RemoveSpaces'],
    ('x:SpamRuleDomain', 'name'): ['Uppercase', 'RemoveSpaces'],
    ('x:SpamRuleEmail', 'name'): ['Uppercase', 'RemoveSpaces'],
    ('x:SpamRuleHeader', 'name'): ['Uppercase', 'RemoveSpaces'],
    ('x:SpamRuleIp', 'name'): ['Uppercase', 'RemoveSpaces'],
    ('x:SpamRuleUrl', 'name'): ['Uppercase', 'RemoveSpaces'],
    ('x:SpamSettings', 'spamFilterRulesUrl'): ['Trim'],
    ('x:SpamTagAction', 'tag'): ['RemoveSpaces', 'Uppercase'],
    ('x:SpamTagScore', 'tag'): ['RemoveSpaces', 'Uppercase'],
    ('x:SqlDirectory', 'columnClass'): ['Trim'],
    ('x:SqlDirectory', 'columnDescription'): ['Trim'],
    ('x:SqlDirectory', 'columnEmail'): ['Trim'],
    ('x:SqlDirectory', 'columnSecret'): ['Trim'],
    ('x:SqlDirectory', 'description'): ['Trim'],
    ('x:SqlDirectory', 'queryEmailAliases'): ['Trim'],
    ('x:SqlDirectory', 'queryLogin'): ['Trim'],
    ('x:SqlDirectory', 'queryMemberOf'): ['Trim'],
    ('x:SqlDirectory', 'queryRecipient'): ['Trim'],
    ('x:SqliteStore', 'path'): ['Trim'],
    ('x:StoreLookup', 'namespace'): ['Trim'],
    ('x:SystemSettings', 'defaultHostname'): ['Hostname'],
    ('x:SystemSettings', 'proxyTrustedNetworks'): ['Trim'],
    ('x:TlsInternalReport', 'domain'): ['Domain'],
    ('x:TlsReportPolicy', 'policyDomain'): ['Domain'],
    ('x:TracerLog', 'path'): ['Trim'],
    ('x:TracerLog', 'prefix'): ['Trim'],
    ('x:TracerOtelGrpc', 'httpHeaders'): ['Trim'],
    ('x:TracerOtelGrpc', 'url'): ['Trim'],
    ('x:TracerOtelHttp', 'httpHeaders'): ['Trim'],
    ('x:TracerOtelHttp', 'url'): ['Trim'],
    ('x:UserAccount', 'name'): ['EmailLocalPart'],
    ('x:WebHook', 'httpHeaders'): ['Trim'],
    ('x:WebHook', 'url'): ['Trim'],
}

# Multi-variant schemas whose variant enum cannot be called <Name>Type
# because schema.json's enum of that name is a different, external enum
# (x:Metric vs trc::MetricType). Enterprise only; the name is ours.
VARIANT_ENUM_NAMES = {
    'x:Metric': 'MetricVariantType',
}

# Fields masked in output unless secrets are requested, besides those whose
# schema format is secret/secretText.
MASKED_FIELDS = {
    ('x:OtpAuth', 'otpUrl'),
    ('x:PasswordCredential', 'otpUrl'),
}

# Fields whose Default impl and/or unpickle fallback are not the schema
# default. spamFilterRulesUrl has no schema default (null means "use the
# bundled rules") but records written before that change still fall back to
# the download URL when the field is missing.
DEFAULT_OVERRIDES = {
    ('x:SpamSettings', 'spamFilterRulesUrl'): {
        'default': 'None',
        'unpickle': 'Some("https://github.com/stalwartlabs/spam-filter/releases/latest/download/spam-filter-rules.json.gz".to_string())',
    },
}

# Expression fields validated only when set (match or else non-empty).
VALIDATE_IF_NOT_EMPTY = {
    ('x:MtaQueueQuota', 'match'),
    ('x:SieveSystemInterpreter', 'defaultReturnPath'),
}

# Numeric fields whose max check is emitted before the min check (schema.json
# always lists min first; upstream's source evidently does not).
VALIDATE_MAX_FIRST = {
    ('x:DnsServerInfoblox', 'port'),
    ('x:DnsServerTsig', 'port'),
    ('x:ElasticSearchStore', 'numShards'),
    ('x:FoundationDbStore', 'transactionRetryLimit'),
    ('x:HttpLookup', 'maxEntries'),
    ('x:HttpLookup', 'maxEntrySize'),
    ('x:HttpLookup', 'maxSize'),
    ('x:MeilisearchStore', 'maxPolls'),
    ('x:MtaMilter', 'port'),
    ('x:MtaRouteRelay', 'port'),
    ('x:MySqlSettings', 'port'),
    ('x:MySqlStore', 'maxAllowedPacket'),
    ('x:MySqlStore', 'poolMaxConnections'),
    ('x:MySqlStore', 'poolMinConnections'),
    ('x:MySqlStore', 'port'),
    ('x:PostgreSqlSettings', 'port'),
    ('x:PostgreSqlStore', 'poolMaxConnections'),
    ('x:PostgreSqlStore', 'port'),
    ('x:RedisClusterStore', 'maxRetries'),
    ('x:RedisClusterStore', 'maxRetryWait'),
    ('x:RedisClusterStore', 'minRetryWait'),
    ('x:RedisClusterStore', 'poolMaxConnections'),
    ('x:RedisSentinelStore', 'poolMaxConnections'),
    ('x:RedisStore', 'poolMaxConnections'),
    ('x:RocksDbStore', 'blobSize'),
    ('x:RocksDbStore', 'bufferSize'),
    ('x:RocksDbStore', 'cacheSize'),
    ('x:RocksDbStore', 'poolWorkers'),
    ('x:SpamClassifier', 'minHamSamples'),
    ('x:SpamClassifier', 'minSpamSamples'),
    ('x:SpamClassifier', 'reservoirCapacity'),
    ('x:SpamPyzor', 'allowCount'),
    ('x:SpamPyzor', 'blockCount'),
    ('x:SpamPyzor', 'port'),
    ('x:SpamPyzor', 'ratio'),
    ('x:SpamRuleAny', 'priority'),
    ('x:SpamRuleBody', 'priority'),
    ('x:SpamRuleDomain', 'priority'),
    ('x:SpamRuleEmail', 'priority'),
    ('x:SpamRuleHeader', 'priority'),
    ('x:SpamRuleIp', 'priority'),
    ('x:SpamRuleUrl', 'priority'),
    ('x:SpamSettings', 'scoreDiscard'),
    ('x:SpamSettings', 'scoreReject'),
    ('x:SpamSettings', 'scoreSpam'),
    ('x:SqliteStore', 'poolMaxConnections'),
    ('x:SqliteStore', 'poolWorkers'),
}

# Expression fields -> (allowed_variables static, allowed_constants static
# or None). Not in the schema. Every Expression field with an entry gets a
# ctx_<field>() method and joins its type's expression_ctxs().
EXPRESSION_CONTEXTS = {
    ('x:Alert', 'condition'): (None, None),
    ('x:DkimReportSettings', 'dkimSignDomain'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DkimReportSettings', 'fromAddress'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DkimReportSettings', 'fromName'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DkimReportSettings', 'sendFrequency'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DkimReportSettings', 'subject'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DmarcReportSettings', 'aggregateContactInfo'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:DmarcReportSettings', 'aggregateDkimSignDomain'): ('MTA_QUEUE_SENDER_VARIABLE', None),
    ('x:DmarcReportSettings', 'aggregateFromAddress'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:DmarcReportSettings', 'aggregateFromName'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:DmarcReportSettings', 'aggregateOrgName'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:DmarcReportSettings', 'aggregateSendFrequency'): ('MTA_RCPT_TO_VARIABLE', 'MTA_AGGREGATE_CONSTANT'),
    ('x:DmarcReportSettings', 'failureDkimSignDomain'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DmarcReportSettings', 'failureFromAddress'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DmarcReportSettings', 'failureFromName'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DmarcReportSettings', 'failureSendFrequency'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DmarcReportSettings', 'failureSubject'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:DmarcReportSettings', 'maxAggregateReportSize'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:DsnReportSettings', 'dkimSignDomain'): ('MTA_QUEUE_SENDER_VARIABLE', None),
    ('x:DsnReportSettings', 'fromAddress'): ('MTA_QUEUE_SENDER_VARIABLE', None),
    ('x:DsnReportSettings', 'fromName'): ('MTA_QUEUE_SENDER_VARIABLE', None),
    ('x:Http', 'allowedEndpoints'): ('HTTP_VARIABLE', None),
    ('x:MtaExtensions', 'chunking'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'deliverBy'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'dsn'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'expn'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'futureRelease'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'mtPriority'): ('MTA_MAIL_FROM_VARIABLE', 'MTA_PRIORITY_CONSTANT'),
    ('x:MtaExtensions', 'noSoliciting'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'pipelining'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'requireTls'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaExtensions', 'vrfy'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaHook', 'enable'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaInboundSession', 'idleTimeout'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaInboundSession', 'maxDuration'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaInboundSession', 'transferLimit'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaInboundThrottle', 'match'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaMilter', 'enable'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaOutboundStrategy', 'connection'): ('MTA_QUEUE_HOST_VARIABLE', None),
    ('x:MtaOutboundStrategy', 'route'): ('MTA_QUEUE_RCPT_VARIABLE', None),
    ('x:MtaOutboundStrategy', 'schedule'): ('MTA_QUEUE_RCPT_VARIABLE', None),
    ('x:MtaOutboundStrategy', 'tls'): ('MTA_QUEUE_HOST_VARIABLE', None),
    ('x:MtaOutboundThrottle', 'match'): ('MTA_QUEUE_HOST_VARIABLE', None),
    ('x:MtaQueueQuota', 'match'): ('MTA_QUEUE_HOST_VARIABLE', None),
    ('x:MtaStageAuth', 'maxFailures'): ('MTA_EHLO_VARIABLE', None),
    ('x:MtaStageAuth', 'mustMatchSender'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaStageAuth', 'require'): ('MTA_EHLO_VARIABLE', None),
    ('x:MtaStageAuth', 'saslMechanisms'): ('MTA_EHLO_VARIABLE', 'MTA_AUTH_TYPE_CONSTANT'),
    ('x:MtaStageAuth', 'waitOnFail'): ('MTA_EHLO_VARIABLE', None),
    ('x:MtaStageConnect', 'hostname'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaStageConnect', 'script'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaStageConnect', 'smtpGreeting'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaStageData', 'addAuthResultsHeader'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'addDateHeader'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'addMessageIdHeader'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'addReceivedHeader'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'addReceivedSpfHeader'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'addReturnPathHeader'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'dkimSignDomain'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'enableSpamFilter'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'maxMessageSize'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'maxMessages'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'maxReceivedHeaders'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageData', 'script'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageEhlo', 'rejectNonFqdn'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaStageEhlo', 'require'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaStageEhlo', 'script'): ('MTA_CONNECTION_VARIABLE', None),
    ('x:MtaStageMail', 'isSenderAllowed'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaStageMail', 'rewrite'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaStageMail', 'script'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaStageRcpt', 'allowRelaying'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageRcpt', 'maxFailures'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaStageRcpt', 'maxRecipients'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:MtaStageRcpt', 'rewrite'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageRcpt', 'script'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:MtaStageRcpt', 'waitOnFail'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:ReportSettings', 'outboundReportSubmitter'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:SenderAuth', 'arcVerify'): ('MTA_RCPT_TO_VARIABLE', 'MTA_VERIFY_CONSTANT'),
    ('x:SenderAuth', 'dkimVerify'): ('MTA_RCPT_TO_VARIABLE', 'MTA_VERIFY_CONSTANT'),
    ('x:SenderAuth', 'dmarcVerify'): ('MTA_RCPT_TO_VARIABLE', 'MTA_VERIFY_CONSTANT'),
    ('x:SenderAuth', 'reverseIpVerify'): ('MTA_CONNECTION_VARIABLE', 'MTA_VERIFY_CONSTANT'),
    ('x:SenderAuth', 'spfEhloVerify'): ('MTA_CONNECTION_VARIABLE', 'MTA_VERIFY_CONSTANT'),
    ('x:SenderAuth', 'spfFromVerify'): ('MTA_CONNECTION_VARIABLE', 'MTA_VERIFY_CONSTANT'),
    ('x:SieveSystemInterpreter', 'defaultFromAddress'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:SieveSystemInterpreter', 'defaultFromName'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:SieveSystemInterpreter', 'defaultReturnPath'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:SieveSystemInterpreter', 'dkimSignDomain'): ('MTA_RCPT_TO_VARIABLE', None),
    ('x:SieveUserInterpreter', 'dkimSignDomain'): ('MTA_QUEUE_SENDER_VARIABLE', None),
    ('x:SpamDnsblServerAny', 'tag'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerAny', 'zone'): ('SPAM_GENERIC_VARIABLE', None),
    ('x:SpamDnsblServerBody', 'tag'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerBody', 'zone'): ('SPAM_GENERIC_VARIABLE', None),
    ('x:SpamDnsblServerDomain', 'tag'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerDomain', 'zone'): ('SPAM_GENERIC_VARIABLE', None),
    ('x:SpamDnsblServerEmail', 'tag'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerEmail', 'zone'): ('SPAM_EMAIL_VARIABLE', None),
    ('x:SpamDnsblServerHeader', 'tag'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerHeader', 'zone'): ('SPAM_HEADER_VARIABLE', None),
    ('x:SpamDnsblServerIp', 'tag'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerIp', 'zone'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerUrl', 'tag'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamDnsblServerUrl', 'zone'): ('SPAM_URL_VARIABLE', None),
    ('x:SpamRuleAny', 'condition'): ('SPAM_GENERIC_VARIABLE', None),
    ('x:SpamRuleBody', 'condition'): ('SPAM_GENERIC_VARIABLE', None),
    ('x:SpamRuleDomain', 'condition'): ('SPAM_GENERIC_VARIABLE', None),
    ('x:SpamRuleEmail', 'condition'): ('SPAM_EMAIL_VARIABLE', None),
    ('x:SpamRuleHeader', 'condition'): ('SPAM_HEADER_VARIABLE', None),
    ('x:SpamRuleIp', 'condition'): ('SPAM_IP_VARIABLE', None),
    ('x:SpamRuleUrl', 'condition'): ('SPAM_URL_VARIABLE', None),
    ('x:SpfReportSettings', 'dkimSignDomain'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:SpfReportSettings', 'fromAddress'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:SpfReportSettings', 'fromName'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:SpfReportSettings', 'sendFrequency'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:SpfReportSettings', 'subject'): ('MTA_MAIL_FROM_VARIABLE', None),
    ('x:SubAddressingCustom', 'customRule'): ('MTA_RCPT_VARIABLE', None),
    ('x:TlsReportSettings', 'contactInfo'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:TlsReportSettings', 'dkimSignDomain'): ('MTA_QUEUE_SENDER_VARIABLE', None),
    ('x:TlsReportSettings', 'fromAddress'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:TlsReportSettings', 'fromName'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:TlsReportSettings', 'maxReportSize'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:TlsReportSettings', 'orgName'): ('MTA_RCPT_DOMAIN_VARIABLE', None),
    ('x:TlsReportSettings', 'sendFrequency'): ('MTA_QUEUE_HOST_VARIABLE', 'MTA_AGGREGATE_CONSTANT'),
}

# Types whose first impl block (ObjectImpl, or the inherent validate impl)
# ends with an Enterprise-only item: the open build keeps the blank line in
# front of it. Its content is not recoverable, so the full edition omits it.
# All are open types that reach a SecretKey/SecretText/PublicText value, but
# not every such type has one (the DnsServer*, *Directory and MtaRoute
# families do not), so this is a list, not a rule.
TRAILING_ENTERPRISE_ITEM = {
    'x:Asn', 'x:AsnResource', 'x:AzureAuth', 'x:AzureAuthClientSecret',
    'x:AzureAuthSasToken', 'x:AzureAuthSharedKey', 'x:AzureStore',
    'x:BlobStore', 'x:BlobStoreSwap', 'x:BlobSwapStore', 'x:Bootstrap',
    'x:Cache', 'x:CacheSwap', 'x:Coordinator', 'x:DataStore',
    'x:DirectoryBootstrap', 'x:DnsServerBootstrap', 'x:ElasticSearchStore',
    'x:HttpAuth', 'x:HttpAuthBasic', 'x:HttpAuthBearer',
    'x:HurricaneCredential', 'x:InMemoryStore', 'x:Jmap', 'x:JokerAuth',
    'x:JokerAuthApiKey', 'x:JokerAuthUsernamePassword', 'x:LookupStore',
    'x:MeilisearchStore', 'x:Metrics', 'x:MetricsOtel', 'x:MetricsOtelHttp',
    'x:MetricsPrometheus', 'x:MetricsPrometheusProperties', 'x:MtaHook',
    'x:MySqlStore', 'x:NatsCoordinator', 'x:OidcProvider',
    'x:PostgreSqlStore', 'x:PublicStringOptional', 'x:PublicText',
    'x:RedisClusterStore', 'x:RedisSentinelStore', 'x:RedisSwap',
    'x:RedisSwapStore', 'x:S3Store', 'x:SearchStore', 'x:SecretKey',
    'x:SecretKeyOptional', 'x:SecretText', 'x:SecretTextOptional',
    'x:SqlAuthStore', 'x:Tracer', 'x:TracerOtelGrpc', 'x:TracerOtelHttp',
    'x:WebHook',
}
