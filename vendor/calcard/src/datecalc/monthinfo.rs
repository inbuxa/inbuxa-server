/*
 * SPDX-FileCopyrightText: 2021 Fredrik Meringdal, Ralph Bisschops <https://github.com/fmeringdal/rust-rrule>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    rrule::{NWeekday, RRule},
    utils::pymod,
    yearinfo::YearInfo,
};
use crate::icalendar::ICalendarFrequency;

#[derive(Debug, Clone)]
pub(crate) struct MonthInfo {
    pub last_year: i32,
    pub last_month: u8,
    pub neg_weekday_mask: Vec<u8>,
}

impl MonthInfo {
    pub fn new(year_info: &YearInfo, month: u8, rrule: &RRule) -> Self {
        let neg_weekday_mask = Self::get_neg_weekday_mask(year_info, month, rrule);
        Self {
            last_year: year_info.year,
            last_month: month,
            neg_weekday_mask,
        }
    }

    fn get_neg_weekday_mask(year_info: &YearInfo, month: u8, rrule: &RRule) -> Vec<u8> {
        let YearInfo {
            year_len,
            month_range,
            weekday_mask,
            ..
        } = year_info;

        // Build up `ranges`
        let mut ranges = vec![];
        if rrule.freq == ICalendarFrequency::Yearly {
            if rrule.by_month.is_empty() {
                ranges.push((0, u32::from(*year_len) - 1));
            } else {
                for month in &rrule.by_month {
                    let month = usize::from(month.month());
                    let first = u32::from(month_range[month - 1]);
                    let last = u32::from(month_range[month]);
                    ranges.push((first, last - 1));
                }
            }
        } else if rrule.freq == ICalendarFrequency::Monthly {
            let month = usize::from(month);
            let first = u32::from(month_range[month - 1]);
            let last = u32::from(month_range[month]);
            ranges.push((first, last - 1));
        }

        if ranges.is_empty() {
            return vec![];
        }

        // Weekly frequency won't get here, so we may not
        // care about cross-year weekly periods.
        let mut neg_weekday_mask = vec![0; usize::from(*year_len)];

        // Loop over `ranges`
        for (first, last) in ranges {
            for by_weekday in &rrule.by_weekday {
                // Only check Nth occurrences here
                if let NWeekday::Nth(number, weekday) = by_weekday {
                    let weekday = (weekday.num_days_from_monday()) as i16;
                    let nth_weekday = if *number < 0 {
                        let number = match u32::try_from(-number) {
                            Ok(num) => num,
                            _ => continue,
                        };
                        let nth_last_week = match last.checked_sub((number - 1) * 7) {
                            Some(val) => val,
                            None => continue,
                        };
                        let index = match usize::try_from(nth_last_week) {
                            Ok(i) => i,
                            _ => continue,
                        };
                        let nth_last_weekday = match weekday_mask.get(index) {
                            Some(val) => (*val) as i16,
                            None => continue,
                        };

                        // Adjust to get the correct weekday
                        let modulo = (pymod(nth_last_weekday - weekday, 7)) as u32;
                        match nth_last_week.checked_sub(modulo) {
                            Some(val) => val,
                            None => continue,
                        }
                    } else {
                        let number = match u32::try_from(number - 1) {
                            Ok(num) => num,
                            _ => continue,
                        };
                        let nth_first_day = first + number * 7;
                        let index = match usize::try_from(nth_first_day) {
                            Ok(i) => i,
                            _ => continue,
                        };
                        let nth_first_day_weekday = match weekday_mask.get(index) {
                            Some(val) => (*val) as i16,
                            None => continue,
                        };

                        // Adjust to get the correct weekday
                        let a = (7 - nth_first_day_weekday + weekday) as u32;
                        nth_first_day + pymod(a, 7)
                    };
                    if first <= nth_weekday
                        && nth_weekday <= last
                        && let Ok(nth_weekday) = usize::try_from(nth_weekday)
                    {
                        neg_weekday_mask[nth_weekday] = 1;
                    }
                }
            }
        }

        neg_weekday_mask
    }
}

#[cfg(test)]
mod tests {
    use crate::common::timezone::Tz;

    use super::*;
    use chrono::{TimeZone, Weekday};

    const UTC: Tz = Tz::Tz(chrono_tz::Tz::UTC);

    #[test]
    fn get_neg_weekday_mask_with_daily_freq() {
        let rrule = RRule {
            freq: ICalendarFrequency::Daily,
            ..Default::default()
        }
        .validate(UTC.with_ymd_and_hms(1997, 1, 1, 0, 0, 0).unwrap())
        .unwrap();

        let year_info = YearInfo::new(1997, &rrule);

        let neg_weekday_mask = MonthInfo::get_neg_weekday_mask(&year_info, 1, &rrule);
        assert!(neg_weekday_mask.is_empty());
    }

    #[test]
    fn get_neg_weekday_mask_with_yearly_freq() {
        let rrule = RRule {
            freq: ICalendarFrequency::Yearly,
            ..Default::default()
        }
        .validate(UTC.with_ymd_and_hms(1997, 1, 1, 0, 0, 0).unwrap())
        .unwrap();

        let year_info = YearInfo::new(1997, &rrule);

        let neg_weekday_mask = MonthInfo::get_neg_weekday_mask(&year_info, 1, &rrule);
        assert_eq!(neg_weekday_mask.len(), year_info.year_len as usize);
        assert!(neg_weekday_mask.into_iter().all(|val| val == 0));
    }

    #[test]
    fn get_neg_weekday_mask_with_yearly_freq_and_byweekday() {
        let rrule = RRule {
            freq: ICalendarFrequency::Yearly,
            by_weekday: vec![
                NWeekday::new(None, Weekday::Mon),
                NWeekday::new(Some(-2), Weekday::Thu),
                NWeekday::new(Some(1), Weekday::Thu),
            ],
            ..Default::default()
        }
        .validate(UTC.with_ymd_and_hms(1997, 1, 1, 0, 0, 0).unwrap())
        .unwrap();

        let year_info = YearInfo::new(1997, &rrule);

        let neg_weekday_mask = MonthInfo::get_neg_weekday_mask(&year_info, 1, &rrule);
        assert_eq!(neg_weekday_mask.len(), year_info.year_len as usize);
        assert!(
            neg_weekday_mask
                .into_iter()
                .enumerate()
                .all(|(idx, val)| match idx {
                    1 | 351 => val == 1,
                    _ => val == 0,
                })
        );
    }

    #[test]
    fn get_neg_weekday_mask_with_monthly_freq_and_byweekday() {
        let rrule = RRule {
            freq: ICalendarFrequency::Monthly,
            by_weekday: vec![
                NWeekday::new(None, Weekday::Mon),
                NWeekday::new(Some(-2), Weekday::Thu),
                NWeekday::new(Some(1), Weekday::Thu),
            ],
            ..Default::default()
        }
        .validate(UTC.with_ymd_and_hms(1997, 1, 1, 0, 0, 0).unwrap())
        .unwrap();

        let year_info = YearInfo::new(1997, &rrule);

        let neg_weekday_mask = MonthInfo::get_neg_weekday_mask(&year_info, 1, &rrule);
        assert_eq!(neg_weekday_mask.len(), year_info.year_len as usize);
        assert!(
            neg_weekday_mask
                .into_iter()
                .enumerate()
                .all(|(idx, val)| match idx {
                    1 | 22 => val == 1,
                    _ => val == 0,
                })
        );
    }
}
