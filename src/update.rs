use chrono::SecondsFormat;
use chrono::Utc;
use cis_profile::crypto::SecretStore;
use cis_profile::crypto::Signer;
use cis_profile::schema::Display;
use cis_profile::schema::Profile;
use cis_profile::schema::PublisherAuthority;
use cis_profile::schema::StandardAttributeString;
use failure::Error;

pub fn update_github(
    github_v4_id: String,
    github_v3_id: String,
    github_email: Option<String>,
    mut profile: Profile,
    store: &SecretStore,
) -> Result<Profile, Error> {
    let now = &Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    update_and_sign(
        &mut profile.identities.github_id_v3,
        github_v3_id,
        store,
        &now,
    )?;
    update_and_sign(
        &mut profile.identities.github_id_v4,
        github_v4_id,
        store,
        &now,
    )?;
    if let Some(email) = github_email {
        update_and_sign(
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
    mut profile: Profile,
    store: &SecretStore,
) -> Result<Profile, Error> {
    let now = &Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    update_and_sign(
        &mut profile.identities.bugzilla_mozilla_org_id,
        bugzilla_id,
        store,
        &now,
    )?;
    update_and_sign(
        &mut profile.identities.bugzilla_mozilla_org_primary_email,
        bugzilla_email,
        store,
        &now,
    )?;
    Ok(profile)
}

fn update_and_sign(
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
