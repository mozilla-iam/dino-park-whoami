use chrono::SecondsFormat;
use chrono::Utc;
use cis_profile::crypto::SecretStore;
use cis_profile::crypto::Signer;
use cis_profile::schema::Display;
use cis_profile::schema::KeyValue;
use cis_profile::schema::Profile;
use cis_profile::schema::PublisherAuthority;
use cis_profile::schema::StandardAttributeString;
use cis_profile::schema::StandardAttributeValues;
use failure::Error;
use std::collections::BTreeMap;
use std::iter::FromIterator;

fn create_usernames_key(typ: &str) -> String {
    format!("HACK#{}", typ)
}

pub fn update_github(
    github_v4_id: String,
    github_v3_id: String,
    github_email: Option<String>,
    github_login: String,
    mut profile: Profile,
    store: &SecretStore,
) -> Result<Profile, Error> {
    let now = &Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    update_and_sign_string_field(
        &mut profile.identities.github_id_v3,
        github_v3_id,
        store,
        &now,
    )?;
    update_and_sign_string_field(
        &mut profile.identities.github_id_v4,
        github_v4_id,
        store,
        &now,
    )?;
    update_and_sign_values_field(
        &mut profile.usernames,
        vec![(create_usernames_key("GITHUB"), github_login)],
        store,
        &now,
    )?;
    if let Some(email) = github_email {
        update_and_sign_string_field(
            &mut profile.identities.github_primary_email,
            email,
            store,
            &now,
        )?;
    }
    Ok(profile)
}

pub fn update_bugzilla(
    bugzilla_id: String,
    bugzilla_email: String,
    bugzilla_nick: Option<String>,
    mut profile: Profile,
    store: &SecretStore,
) -> Result<Profile, Error> {
    let now = &Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    update_and_sign_string_field(
        &mut profile.identities.bugzilla_mozilla_org_id,
        bugzilla_id,
        store,
        &now,
    )?;
    update_and_sign_string_field(
        &mut profile.identities.bugzilla_mozilla_org_primary_email,
        bugzilla_email.clone(),
        store,
        &now,
    )?;

    let mut kv_pairs = vec![(create_usernames_key("BMOMAIL"), bugzilla_email)];
    if let Some(nick) = bugzilla_nick {
        kv_pairs.push((create_usernames_key("BMONICK"), nick));
    }
    update_and_sign_values_field(&mut profile.usernames, kv_pairs, store, &now)?;
    Ok(profile)
}

fn update_and_sign_values_field(
    field: &mut StandardAttributeValues,
    kv_pairs: Vec<(String, String)>,
    store: &SecretStore,
    now: &str,
) -> Result<(), Error> {
    if let Some(KeyValue(ref mut values)) = &mut field.values {
        for (k, v) in kv_pairs.into_iter() {
            values.insert(k, Some(v));
        }
    } else {
        field.values = Some(KeyValue(BTreeMap::from_iter(
            kv_pairs.into_iter().map(|(k, v)| (k, Some(v))),
        )))
    }
    if field.metadata.display.is_none() {
        field.metadata.display = Some(Display::Staff);
    }
    field.metadata.last_modified = now.to_owned();
    field.signature.publisher.name = PublisherAuthority::Mozilliansorg;
    store.sign_attribute(field)
}

fn update_and_sign_string_field(
    field: &mut StandardAttributeString,
    value: String,
    store: &SecretStore,
    now: &str,
) -> Result<(), Error> {
    field.value = Some(value);
    if field.metadata.display.is_none() {
        field.metadata.display = Some(Display::Staff);
    }
    field.metadata.last_modified = now.to_owned();
    field.signature.publisher.name = PublisherAuthority::Mozilliansorg;
    store.sign_attribute(field)
}
