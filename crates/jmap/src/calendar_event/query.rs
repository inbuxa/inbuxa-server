/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::{
        metadata::{
            MetadataType, ObjectMetadata, ResourceScope, filter_containers, flagged_documents,
        },
        query::QueryResponseBuilder,
    },
    changes::state::JmapCacheState,
};
use calcard::{common::timezone::Tz, icalendar::ArchivedICalendar, jscalendar::JSCalendarDateTime};
use common::{
    GroupwareResourceRef, GroupwareResources, Server, auth::AccessToken,
    storage::batch::MAX_BATCH_DOCUMENTS,
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEventContent, EVENT_FLOATING_START, EVENT_HIDE_ATTENDEES, EVENT_PRIVATE,
        EVENT_SECRET,
        expand::{MAX_UTC_OFFSET, resolve_local},
        identity::{CalendarAddresses, ParticipantIdentityAddresses},
        instance_filter::{AttendeeSearch, InstanceTextFilter},
    },
};
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::{
        calendar::{self, CalendarFilter},
        calendar_event::{self, CalendarEventComparator, CalendarEventFilter},
    },
    request::{MaybeInvalid, capability::CapabilityIds},
};
use nlp::language::Language;
use std::cmp::Ordering;
use store::{
    ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    search::{CalendarSearchField, QueryResults, SearchComparator, SearchFilter, SearchQuery},
    write::{Archive, ArchiveBytes, SearchIndex},
};
use trc::AddContext;
use types::{
    OverlapRule, TimeRange,
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};

pub trait CalendarEventQuery: Sync + Send {
    fn calendar_event_query(
        &self,
        request: QueryRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;

    fn calendar_query(
        &self,
        request: QueryRequest<calendar::Calendar>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl CalendarEventQuery for Server {
    async fn calendar_event_query(
        &self,
        mut request: QueryRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::CalendarEvent);
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let metadata_query =
            metadata.query(request.filter.iter().filter_map(|filter| match filter {
                Filter::Property(CalendarEventFilter::Metadata(filter)) => Some(filter),
                _ => None,
            }))?;
        let mut filters = Vec::with_capacity(request.filter.len());
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let default_tz = request.arguments.resolved_time_zone()?;
        let default_language = self.core.email.default_language;
        let is_member = access_token.is_member(account_id);
        let expand_recurrences = request.arguments.expand_recurrences.unwrap_or(false);
        let mut filter: Option<TimeRange> = None;
        let mut instance_filter = InstanceTextFilter::default();

        if expand_recurrences
            && (request
                .filter
                .iter()
                .any(|cond| matches!(cond, Filter::Or | Filter::Not))
                || request
                    .filter
                    .iter()
                    .filter(|cond| matches!(cond, Filter::And))
                    .count()
                    > 1)
        {
            return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                "The filter must be a single FilterCondition when expanding recurrences",
            ));
        }

        if expand_recurrences
            && let Some(unsupported) =
                request
                    .sort
                    .iter()
                    .flatten()
                    .find_map(|comparator| match &comparator.property {
                        CalendarEventComparator::_T(property) => Some(property),
                        _ => None,
                    })
        {
            return Err(trc::JmapEvent::UnsupportedSort
                .into_err()
                .details(unsupported.clone()));
        }

        let is_shared = access_token.is_shared(account_id);
        let hides_text = !is_member
            && request.filter.iter().any(|cond| {
                matches!(
                    cond,
                    Filter::Property(
                        CalendarEventFilter::Text(_)
                            | CalendarEventFilter::Title(_)
                            | CalendarEventFilter::Description(_)
                            | CalendarEventFilter::Location(_)
                            | CalendarEventFilter::Owner(_)
                            | CalendarEventFilter::Participant(_)
                    )
                )
            });
        let [secret_ids, private_ids, hidden_attendee_ids] = if is_shared || hides_text {
            cache.event_ids_with_flag_masks([
                EVENT_SECRET,
                EVENT_PRIVATE | EVENT_SECRET,
                EVENT_HIDE_ATTENDEES,
            ])
        } else {
            std::array::from_fn(|_| RoaringBitmap::new())
        };
        let mask = if is_shared {
            let mut shared_ids = cache.shared_items(access_token, [Acl::ReadItems], true);
            shared_ids -= secret_ids;
            shared_ids
        } else {
            cache.document_ids(false).collect()
        };
        let metadata_hidden =
            (is_shared && !metadata_query.is_empty()).then(|| private_ids.clone());
        let searches_attendees = !is_member
            && request.filter.iter().any(|cond| {
                matches!(
                    cond,
                    Filter::Property(
                        CalendarEventFilter::Text(_) | CalendarEventFilter::Participant(_)
                    )
                )
            });
        let hidden_attendees = searches_attendees
            .then(|| HiddenAttendees::new(&cache, access_token, &hidden_attendee_ids))
            .flatten();
        let identities = match &hidden_attendees {
            Some(_) => Some(
                self.account_identity_addresses(access_token.account_id())
                    .await
                    .caused_by(trc::location!())?,
            ),
            None => None,
        };
        let visibility = if hides_text {
            TextVisibility::new(
                &cache,
                private_ids,
                hidden_attendees
                    .as_ref()
                    .filter(|_| !expand_recurrences)
                    .map(|hidden| hidden.filtered.clone())
                    .unwrap_or_default(),
            )
        } else {
            TextVisibility::default()
        };
        let attendee_matches = match (&hidden_attendees, &identities) {
            (Some(hidden), Some(identities)) if !expand_recurrences => Some(VisibleAttendees {
                hidden,
                identities,
                account_id,
                mask: &mask,
                default_language,
            }),
            _ => None,
        };
        let mut metadata_leaves = metadata
            .evaluate(self, account_id, &metadata_query, || {
                let mut flagged =
                    flagged_documents(&cache, ResourceScope::Items, is_shared.then_some(&mask));
                if let Some(hidden) = &metadata_hidden {
                    flagged -= hidden;
                }
                flagged
            })
            .await?
            .into_iter();
        let candidates = if expand_recurrences {
            BoundCandidates::Widened
        } else {
            BoundCandidates::Exact
        };

        // Extract from/to arguments
        for cond in &request.filter {
            if let Filter::Property(CalendarEventFilter::After(date)) = cond {
                if let Some(after) = local_timestamp(date, default_tz) {
                    filter.get_or_insert_default().start = after;
                }
            } else if let Filter::Property(CalendarEventFilter::Before(date)) = cond
                && let Some(before) = local_timestamp(date, default_tz)
            {
                filter.get_or_insert_default().end = before;
            }
        }

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    CalendarEventFilter::InCalendar(MaybeInvalid::Value(id)) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )))
                    }
                    CalendarEventFilter::Uid(value) => {
                        filters.push(SearchFilter::is_in_set(cache.uid_matches(&value)));
                    }
                    CalendarEventFilter::Text(value) => {
                        let (text, language) = Language::detect(value, default_language);
                        let filter =
                            SearchFilter::has_text(CalendarSearchField::Title, text, language);
                        if expand_recurrences {
                            instance_filter.add(TEXT_FIELDS, &filter);
                        }
                        let verified = match &attendee_matches {
                            Some(matches) => Some(matches.of(self, &filter).await?),
                            None => None,
                        };
                        visibility.push_any_field(&mut filters, filter, TEXT_FIELDS, verified);
                    }
                    CalendarEventFilter::Title(title) => {
                        let filter = SearchFilter::has_text_detect(
                            CalendarSearchField::Title,
                            title,
                            default_language,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Title], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Description(description) => {
                        let filter = SearchFilter::has_text_detect(
                            CalendarSearchField::Description,
                            description,
                            default_language,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Description], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Location(location) => {
                        let filter = SearchFilter::has_text_detect(
                            CalendarSearchField::Location,
                            location,
                            default_language,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Location], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Owner(owner) => {
                        let filter = SearchFilter::has_text(
                            CalendarSearchField::Owner,
                            owner,
                            Language::None,
                        );
                        if expand_recurrences {
                            instance_filter.add(&[CalendarSearchField::Owner], &filter);
                        }
                        visibility.push(&mut filters, filter);
                    }
                    CalendarEventFilter::Participant(participant) => {
                        let filter = SearchFilter::has_text(
                            CalendarSearchField::Owner,
                            participant,
                            Language::None,
                        );
                        if expand_recurrences {
                            instance_filter.add(PARTICIPANT_FIELDS, &filter);
                        }
                        let verified = match &attendee_matches {
                            Some(matches) => Some(matches.of(self, &filter).await?),
                            None => None,
                        };
                        visibility.push_any_field(
                            &mut filters,
                            filter,
                            PARTICIPANT_FIELDS,
                            verified,
                        );
                    }
                    CalendarEventFilter::After(after) => {
                        if let Some(after) = local_timestamp(&after, default_tz) {
                            filters.push(SearchFilter::is_in_set(
                                TimeBound::After(after)
                                    .event_ids(self, &cache, account_id, default_tz, candidates)
                                    .await?,
                            ));
                        }
                    }
                    CalendarEventFilter::Before(before) => {
                        if let Some(before) = local_timestamp(&before, default_tz) {
                            filters.push(SearchFilter::is_in_set(
                                TimeBound::Before(before)
                                    .event_ids(self, &cache, account_id, default_tz, candidates)
                                    .await?,
                            ));
                        }
                    }
                    CalendarEventFilter::Metadata(_) => {
                        let mut matches = metadata_leaves.next().unwrap_or_default();
                        if let Some(hidden) = &metadata_hidden {
                            matches -= hidden;
                        }
                        filters.push(SearchFilter::is_in_set(matches));
                    }
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(unsupported.into_string()));
                    }
                },
                Filter::And => {
                    filters.push(SearchFilter::And);
                }
                Filter::Or => {
                    filters.push(SearchFilter::Or);
                }
                Filter::Not => {
                    filters.push(SearchFilter::Not);
                }
                Filter::Close => {
                    filters.push(SearchFilter::End);
                }
            }
        }

        let expand_range = if expand_recurrences {
            let Some(time_range) = filter.filter(|f| f.start != i64::MIN && f.end != i64::MAX)
            else {
                return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                    "Both 'after' and 'before' filters are required when expanding recurrences",
                ));
            };
            if time_range.end.saturating_sub(time_range.start)
                > self.core.groupware.max_expanded_query_duration as i64
            {
                return Err(trc::JmapEvent::ExpandDurationTooLarge.into_err().details(
                    "The time span between 'after' and 'before' exceeds maxExpandedQueryDuration",
                ));
            }
            Some(time_range)
        } else {
            None
        };
        let sort = if !expand_recurrences {
            request
                .sort
                .take()
                .unwrap_or_default()
                .into_iter()
                .map(|comparator| {
                    let key = match comparator.property {
                        CalendarEventComparator::Id => EventSortKey::Id,
                        CalendarEventComparator::Start => EventSortKey::Start,
                        CalendarEventComparator::Uid => EventSortKey::Uid,
                        CalendarEventComparator::Created => EventSortKey::Created,
                        CalendarEventComparator::Updated => EventSortKey::Updated,
                        CalendarEventComparator::_T(other) => {
                            return Err(trc::JmapEvent::UnsupportedSort.into_err().details(other));
                        }
                    };
                    Ok((key, comparator.is_ascending))
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![]
        };

        let results = self
            .search_store()
            .filter_account(
                SearchQuery::new(SearchIndex::Calendar)
                    .with_filters(filters)
                    .with_account_id(account_id)
                    .with_mask(mask),
            )
            .await?;
        let sort = EventSortKey::until_unique(sort);
        let results = if results.len() > 1 && !sort.is_empty() {
            if let [(EventSortKey::Id, is_ascending)] = sort.as_slice() {
                let mut results = results.into_iter().collect::<Vec<_>>();
                if !is_ascending {
                    results.reverse();
                }
                results
            } else {
                let items = matched_items(&cache, &results);
                let comparators = sort
                    .into_iter()
                    .map(|(key, is_ascending)| match key {
                        EventSortKey::Id => {
                            rank_comparator(&items, |item| Some(item.document_id()), is_ascending)
                        }
                        EventSortKey::Start => {
                            let floating_tz = (!default_tz.is_utc()).then_some(default_tz);
                            rank_comparator(
                                &items,
                                |item| item.event_start(floating_tz),
                                is_ascending,
                            )
                        }
                        EventSortKey::Uid => {
                            rank_comparator(&items, |item| item.uid(), is_ascending)
                        }
                        EventSortKey::Created => {
                            rank_comparator(&items, |item| item.created_at(), is_ascending)
                        }
                        EventSortKey::Updated => {
                            rank_comparator(&items, |item| item.modified_at(), is_ascending)
                        }
                    })
                    .collect();
                QueryResults::new(results, comparators).into_sorted()
            }
        } else {
            results.into_iter().collect()
        };
        let query_state = sampled.state(cache.get_state(false));

        // Extract comparators
        let comparators = request
            .sort
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or_default();

        if let Some(time_range) = expand_range {
            let max_instances = self.core.groupware.max_ical_instances;
            let mut expanded_results = Vec::with_capacity(results.len() as usize);

            for document_id in results {
                let Some(resource) = cache.item_by_id(document_id) else {
                    continue;
                };
                let Some(_content) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await?
                else {
                    continue;
                };
                let content = _content
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?;
                let event = &content.data.event;
                let mut scheduling_components = event
                    .components
                    .iter()
                    .filter(|component| component.component_type.is_scheduling_object());
                let is_recurring =
                    match (scheduling_components.next(), scheduling_components.next()) {
                        (Some(component), None) => component.is_recurrent(),
                        _ => true,
                    };
                let attendees = match (&hidden_attendees, &identities) {
                    (Some(hidden), Some(identities))
                        if hidden.is_filtered(document_id, event, identities) =>
                    {
                        AttendeeSearch::VisibleTo(identities)
                    }
                    _ => AttendeeSearch::All,
                };
                let event_filter = (!instance_filter.is_empty())
                    .then(|| instance_filter.for_event(event, default_language, attendees));
                let mut component_matches: Vec<(u32, bool)> = Vec::new();
                let created = resource.created_at().unwrap_or_default();
                let updated = resource.modified_at().unwrap_or_default();
                let uid = resource.uid().unwrap_or_default();

                for expansion in content
                    .data
                    .expand(default_tz, time_range, OverlapRule::Jmap)
                    .unwrap_or_default()
                {
                    let prefix = match (is_recurring, expansion.recurrence_key()) {
                        (false, _) => 0,
                        (true, Some(recurrence_key)) => recurrence_key.prefix(),
                        (true, None) => continue,
                    };
                    if let Some(event_filter) = &event_filter {
                        let is_match = match component_matches
                            .iter()
                            .find(|(comp_id, _)| *comp_id == expansion.comp_id)
                        {
                            Some((_, is_match)) => *is_match,
                            None => {
                                let is_match = event
                                    .components
                                    .get(expansion.comp_id as usize)
                                    .is_some_and(|component| event_filter.matches(component));
                                component_matches.push((expansion.comp_id, is_match));
                                is_match
                            }
                        };
                        if !is_match {
                            continue;
                        }
                    }
                    if expanded_results.len() >= max_instances {
                        return Err(trc::JmapEvent::CannotCalculateOccurrences
                            .into_err()
                            .details(
                                "The number of expanded recurrences exceeds the server limit",
                            ));
                    }
                    expanded_results.push(ExpandedResult {
                        prefix,
                        document_id,
                        start: expansion.start,
                        created,
                        updated,
                        uid,
                    });
                }
            }

            let mut response = QueryResponseBuilder::new(
                expanded_results.len(),
                self.core.jmap.query_max_results,
                query_state,
                &request,
            );
            response.response.can_calculate_changes = false;
            expanded_results.sort_by(|a, b| {
                comparators
                    .iter()
                    .map(|comparator| {
                        let ordering = a.cmp_by(b, &comparator.property);
                        if comparator.is_ascending {
                            ordering
                        } else {
                            ordering.reverse()
                        }
                    })
                    .find(|ordering| ordering.is_ne())
                    .unwrap_or(Ordering::Equal)
            });
            for result in expanded_results {
                if !response.add(result.prefix, result.document_id) {
                    break;
                }
            }
            response.build()
        } else {
            let mut response = QueryResponseBuilder::new(
                results.len(),
                self.core.jmap.query_max_results,
                query_state,
                &request,
            );
            for document_id in results {
                if !response.add(0, document_id) {
                    break;
                }
            }
            response.build()
        }
    }

    async fn calendar_query(
        &self,
        request: QueryRequest<calendar::Calendar>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<QueryResponse> {
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::Calendar);
        let mut metadata_filters = Vec::new();
        for filter in &request.filter {
            match filter {
                Filter::Property(CalendarFilter::Metadata(filter)) => {
                    metadata_filters.push(filter);
                }
                Filter::Property(CalendarFilter::_T(other)) => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details(other.clone()));
                }
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {}
            }
        }
        let metadata_query = metadata.query(metadata_filters)?;

        let account_id = request.account_id.document_id();
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;

        let is_member = access_token.is_member(account_id);
        let readable = if is_member {
            cache.document_ids(true).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
        };
        let leaves = metadata
            .evaluate(self, account_id, &metadata_query, || {
                flagged_documents(
                    &cache,
                    ResourceScope::Containers,
                    (!is_member).then_some(&readable),
                )
            })
            .await?;
        let results = filter_containers(&request.filter, leaves, readable);

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            sampled.state(cache.get_state(true)),
            &request,
        );

        for document_id in results {
            if !response.add(0, document_id) {
                break;
            }
        }

        response.build()
    }
}

const ITEM_LOOKUP_RATIO: u64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventSortKey {
    Id,
    Start,
    Uid,
    Created,
    Updated,
}

impl EventSortKey {
    fn until_unique(mut sort: Vec<(EventSortKey, bool)>) -> Vec<(EventSortKey, bool)> {
        if let Some(position) = sort.iter().position(|(key, _)| *key == EventSortKey::Id) {
            sort.truncate(position + 1);
            if position > 0 && sort.last().is_some_and(|(_, is_ascending)| *is_ascending) {
                sort.pop();
            }
        }
        sort
    }
}

trait EventStart {
    fn event_start(&self, floating_tz: Option<Tz>) -> Option<i64>;
}

impl EventStart for GroupwareResourceRef<'_> {
    fn event_start(&self, floating_tz: Option<Tz>) -> Option<i64> {
        let (start, _) = self.event_time_range()?;
        Some(
            match floating_tz.filter(|_| {
                self.event_flags()
                    .is_some_and(|flags| flags & EVENT_FLOATING_START != 0)
            }) {
                Some(tz) => resolve_local(tz, start).unwrap_or(start),
                None => start,
            },
        )
    }
}

pub(crate) fn matched_items<'x>(
    cache: &'x GroupwareResources,
    results: &RoaringBitmap,
) -> Vec<GroupwareResourceRef<'x>> {
    let mut items = Vec::with_capacity(results.len() as usize);
    if results.len().saturating_mul(ITEM_LOOKUP_RATIO) < cache.resources.len() as u64 {
        items.extend(
            results
                .iter()
                .filter_map(|document_id| cache.item_by_id(document_id)),
        );
    } else {
        let mut ids = results.iter().peekable();
        for resource in cache.resources.iter_run(false) {
            let document_id = resource.document_id();
            while ids.next_if(|id| *id < document_id).is_some() {}
            if ids.next_if_eq(&document_id).is_some() && !resource.is_container() {
                items.push(resource);
            }
            if ids.peek().is_none() {
                break;
            }
        }
    }
    items
}

pub(crate) fn rank_comparator<'x, K: Ord>(
    items: &[GroupwareResourceRef<'x>],
    key: impl Fn(&GroupwareResourceRef<'x>) -> Option<K>,
    is_ascending: bool,
) -> SearchComparator {
    let mut keys = items
        .iter()
        .filter_map(|item| key(item).map(|key| (key, item.document_id())))
        .collect::<Vec<_>>();
    keys.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
    let mut ranks = AHashMap::with_capacity(keys.len());
    let mut rank = 0u32;
    let mut previous = None;
    for (key, document_id) in &keys {
        if previous.is_some_and(|previous| previous != key) {
            rank += 1;
        }
        previous = Some(key);
        ranks.insert(*document_id, rank);
    }
    SearchComparator::sorted_set(ranks, is_ascending)
}

fn local_timestamp(dt: &JSCalendarDateTime, tz: Tz) -> Option<i64> {
    tz.from_local(dt.to_naive_date_time()?)
        .map(|dt| dt.timestamp())
}

#[derive(Debug)]
struct ExpandedResult<'x> {
    prefix: u32,
    document_id: u32,
    start: i64,
    created: i64,
    updated: i64,
    uid: &'x str,
}

impl ExpandedResult<'_> {
    fn cmp_by(&self, other: &Self, comparator: &CalendarEventComparator) -> Ordering {
        match comparator {
            CalendarEventComparator::Id => {
                (self.prefix, self.document_id).cmp(&(other.prefix, other.document_id))
            }
            CalendarEventComparator::Start => self.start.cmp(&other.start),
            CalendarEventComparator::Uid => self.uid.cmp(other.uid),
            CalendarEventComparator::Created => self.created.cmp(&other.created),
            CalendarEventComparator::Updated => self.updated.cmp(&other.updated),
            CalendarEventComparator::_T(_) => Ordering::Equal,
        }
    }
}

#[derive(Debug, Default)]
struct TextVisibility {
    public_ids: Option<RoaringBitmap>,
    attendee_ids: Option<RoaringBitmap>,
}

impl TextVisibility {
    fn new(
        cache: &GroupwareResources,
        private_ids: RoaringBitmap,
        hidden_attendee_ids: RoaringBitmap,
    ) -> Self {
        if private_ids.is_empty() && hidden_attendee_ids.is_empty() {
            return TextVisibility::default();
        }
        let all_ids = cache.document_ids(false).collect::<RoaringBitmap>();
        let visible_ids =
            |hidden_ids: RoaringBitmap| (!hidden_ids.is_empty()).then(|| &all_ids - hidden_ids);

        TextVisibility {
            public_ids: visible_ids(private_ids),
            attendee_ids: visible_ids(hidden_attendee_ids),
        }
    }

    fn push(&self, filters: &mut Vec<SearchFilter>, filter: SearchFilter) {
        match &self.public_ids {
            Some(public_ids) => {
                filters.push(SearchFilter::And);
                filters.push(filter);
                filters.push(SearchFilter::is_in_set(public_ids.clone()));
                filters.push(SearchFilter::End);
            }
            None => filters.push(filter),
        }
    }

    fn push_any_field(
        &self,
        filters: &mut Vec<SearchFilter>,
        filter: SearchFilter,
        fields: &[CalendarSearchField],
        visible_attendees: Option<RoaringBitmap>,
    ) {
        let SearchFilter::Text {
            op,
            value,
            language,
            ..
        } = filter
        else {
            return;
        };
        if self.public_ids.is_some() {
            filters.push(SearchFilter::And);
        }
        filters.push(SearchFilter::Or);
        for field in fields
            .iter()
            .filter(|field| **field != CalendarSearchField::Attendee)
        {
            filters.push(SearchFilter::Text {
                field: (*field).into(),
                op,
                value: value.clone(),
                language,
            });
        }
        let attendee = SearchFilter::Text {
            field: CalendarSearchField::Attendee.into(),
            op,
            value,
            language,
        };
        match &self.attendee_ids {
            Some(attendee_ids) => {
                filters.push(SearchFilter::And);
                filters.push(attendee);
                filters.push(SearchFilter::is_in_set(attendee_ids.clone()));
                filters.push(SearchFilter::End);
            }
            None => filters.push(attendee),
        }
        if let Some(visible_attendees) = visible_attendees.filter(|ids| !ids.is_empty()) {
            filters.push(SearchFilter::is_in_set(visible_attendees));
        }
        filters.push(SearchFilter::End);
        if let Some(public_ids) = &self.public_ids {
            filters.push(SearchFilter::is_in_set(public_ids.clone()));
            filters.push(SearchFilter::End);
        }
    }
}

struct HiddenAttendees {
    filtered: RoaringBitmap,
    writable: RoaringBitmap,
}

struct VisibleAttendees<'x> {
    hidden: &'x HiddenAttendees,
    identities: &'x CalendarAddresses,
    account_id: u32,
    mask: &'x RoaringBitmap,
    default_language: Language,
}

impl HiddenAttendees {
    fn new(
        cache: &GroupwareResources,
        access_token: &AccessToken,
        hidden_ids: &RoaringBitmap,
    ) -> Option<Self> {
        if hidden_ids.is_empty() {
            return None;
        }
        let write_all = cache.shared_containers(access_token, [Acl::ModifyItems], true);
        let write_own =
            cache.shared_containers(access_token, [Acl::ModifyItems, Acl::ModifyItemsOwn], true);
        let mut filtered = RoaringBitmap::new();
        let mut writable = RoaringBitmap::new();
        for document_id in hidden_ids {
            let Some(resource) = cache.item_by_id(document_id) else {
                continue;
            };
            let calendar_ids = resource.child_names();
            if !calendar_ids
                .iter()
                .all(|name| write_all.contains(name.parent_id))
            {
                filtered.insert(document_id);
                if calendar_ids
                    .iter()
                    .all(|name| write_own.contains(name.parent_id))
                {
                    writable.insert(document_id);
                }
            }
        }
        (!filtered.is_empty()).then_some(HiddenAttendees { filtered, writable })
    }

    fn is_filtered(
        &self,
        document_id: u32,
        event: &ArchivedICalendar,
        identities: &CalendarAddresses,
    ) -> bool {
        self.filtered.contains(document_id)
            && !(self.writable.contains(document_id)
                && identities.archived_event_ownership(event).may_write_own())
    }
}

impl VisibleAttendees<'_> {
    async fn of(&self, server: &Server, filter: &SearchFilter) -> trc::Result<RoaringBitmap> {
        let mut candidates = &self.hidden.filtered & self.mask;
        let SearchFilter::Text {
            op,
            value,
            language,
            ..
        } = filter
        else {
            return Ok(RoaringBitmap::new());
        };
        if candidates.is_empty() {
            return Ok(candidates);
        }
        let attendee = SearchFilter::Text {
            field: CalendarSearchField::Attendee.into(),
            op: *op,
            value: value.clone(),
            language: *language,
        };
        let mut text_filter = InstanceTextFilter::default();
        text_filter.add(&[CalendarSearchField::Attendee], &attendee);
        candidates = server
            .search_store()
            .filter_account(
                SearchQuery::new(SearchIndex::Calendar)
                    .with_filters(vec![attendee])
                    .with_account_id(self.account_id)
                    .with_mask(candidates),
            )
            .await?;

        let mut matches = RoaringBitmap::new();
        let mut chunk = Vec::new();
        let mut candidates = candidates.iter();
        loop {
            chunk.clear();
            chunk.extend(candidates.by_ref().take(MAX_BATCH_DOCUMENTS));
            if chunk.is_empty() {
                break;
            }
            server
                .archives(
                    self.account_id,
                    Collection::CalendarEvent,
                    CalendarEventField::Content.into(),
                    &chunk,
                    |document_id, archive| {
                        let event = &archive
                            .unarchive::<CalendarEventContent>()
                            .caused_by(trc::location!())?
                            .data
                            .event;
                        let is_match =
                            !self.hidden.is_filtered(document_id, event, self.identities) || {
                                let filter = text_filter.for_event(
                                    event,
                                    self.default_language,
                                    AttendeeSearch::VisibleTo(self.identities),
                                );
                                event
                                    .components
                                    .iter()
                                    .filter(|component| {
                                        component.component_type.is_scheduling_object()
                                    })
                                    .any(|component| filter.matches(component))
                            };
                        if is_match {
                            matches.insert(document_id);
                        }
                        Ok(true)
                    },
                )
                .await?;
        }
        Ok(matches)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundCandidates {
    Widened,
    Exact,
}

#[derive(Debug, Clone, Copy)]
enum TimeBound {
    After(i64),
    Before(i64),
}

impl TimeBound {
    fn matches(self, (start, end): (i64, i64), margin: i64) -> bool {
        match self {
            TimeBound::After(after) => after.saturating_sub(margin) < end,
            TimeBound::Before(before) => before.saturating_add(margin) > start,
        }
    }

    fn time_range(self) -> TimeRange {
        match self {
            TimeBound::After(after) => TimeRange::new(after, i64::MAX),
            TimeBound::Before(before) => TimeRange::new(i64::MIN, before),
        }
    }

    async fn event_ids(
        self,
        server: &Server,
        cache: &GroupwareResources,
        account_id: u32,
        default_tz: Tz,
        candidates: BoundCandidates,
    ) -> trc::Result<RoaringBitmap> {
        let margin = if default_tz.is_utc() {
            0
        } else {
            MAX_UTC_OFFSET
        };
        let mut event_ids = RoaringBitmap::new();

        for resource in cache.resources.iter_run(false) {
            let Some(range) = resource.event_time_range() else {
                continue;
            };
            let document_id = resource.document_id();
            if self.matches(range, -margin)
                || (self.matches(range, margin)
                    && (candidates == BoundCandidates::Widened
                        || self
                            .contains_instance(server, account_id, document_id, default_tz)
                            .await?))
            {
                event_ids.insert(document_id);
            }
        }

        Ok(event_ids)
    }

    async fn contains_instance(
        self,
        server: &Server,
        account_id: u32,
        document_id: u32,
        default_tz: Tz,
    ) -> trc::Result<bool> {
        let Some(archive) = server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                account_id,
                Collection::CalendarEvent,
                document_id,
                CalendarEventField::Content,
            ))
            .await?
        else {
            return Ok(false);
        };

        Ok(archive
            .unarchive::<CalendarEventContent>()
            .caused_by(trc::location!())?
            .data
            .expand(default_tz, self.time_range(), OverlapRule::Jmap)
            .is_some_and(|instances| !instances.is_empty()))
    }
}

const TEXT_FIELDS: &[CalendarSearchField] = &[
    CalendarSearchField::Title,
    CalendarSearchField::Description,
    CalendarSearchField::Location,
    CalendarSearchField::Owner,
    CalendarSearchField::Attendee,
];
const PARTICIPANT_FIELDS: &[CalendarSearchField] =
    &[CalendarSearchField::Owner, CalendarSearchField::Attendee];
