/*
 * SPDX-FileCopyrightText: 2026 Coffey Labs LLC
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

//! Templates (§2.3): named sets of detectors, so a policy doesn't pick forty
//! one at a time. Each is named for what it finds, never for a law, and is a
//! starting point: once added to a rule, its detectors can be changed.

pub struct Template {
    pub id: &'static str,
    pub name: &'static str,
    pub detectors: &'static [&'static str],
}

pub static TEMPLATES: &[Template] = &[
    Template {
        id: "payment-and-bank",
        name: "Payment cards and bank accounts",
        detectors: &["payment-card", "iban", "swift-bic", "us-aba-routing"],
    },
    Template {
        id: "us-personal",
        name: "US personal identifiers",
        detectors: &[
            "us-ssn",
            "us-itin",
            "us-ein",
            "us-drivers-license",
            "passport",
            "date-of-birth",
        ],
    },
    Template {
        id: "uk-personal",
        name: "UK personal identifiers",
        detectors: &["uk-nino", "uk-utr", "uk-nhs", "passport", "date-of-birth"],
    },
    Template {
        id: "eu-national",
        name: "EU national identifiers",
        detectors: &[
            "de-tax-id",
            "de-id-card",
            "fr-nir",
            "es-dni-nie",
            "it-codice-fiscale",
            "nl-bsn",
            "be-national-number",
            "pl-pesel",
            "se-personnummer",
            "dk-cpr",
            "fi-hetu",
            "ie-pps",
            "pt-nif",
            "at-svnr",
        ],
    },
    Template {
        id: "health",
        name: "Health identifiers",
        detectors: &["uk-nhs", "us-mbi", "us-npi", "us-dea", "au-medicare"],
    },
    Template {
        id: "credentials",
        name: "Credentials and keys",
        detectors: &["private-key", "credentials"],
    },
    Template {
        id: "contact-lists",
        name: "Contact lists",
        detectors: &["email-addresses", "phone-numbers"],
    },
];

pub fn by_id(id: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|template| template.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_names_real_detectors() {
        for template in TEMPLATES {
            for id in template.detectors {
                assert!(
                    super::super::by_id(id).is_some(),
                    "{}: no detector {id}",
                    template.id
                );
            }
        }
    }
}
