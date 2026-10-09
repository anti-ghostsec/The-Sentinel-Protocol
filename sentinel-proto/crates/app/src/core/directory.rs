//! Which Pillars to try when connecting, so a directory full of gone
//! Pillars never slows the start:
//!
//! - **Remember what worked.** Each known Pillar keeps the day it last
//!   answered and how many tries in a row failed (days only: nothing finer
//!   about when you were online is kept). Pillars that worked lately are
//!   tried first; ones failing today wait; ones silent for a week are
//!   forgotten.
//! - **Vouched Pillars.** Credit issuers sign a list of Pillars that have
//!   answered their random checks for weeks (`sentinel_core::directory`);
//!   those are tried early, so fake or dead entries can't crowd them out.
//! - **Race a mix.** The first round tries a few of each kind at once
//!   (each on its own circuit) and starts with whichever answers first.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{request, Core, Store};
use sentinel_core::wire::{Request, Response};
use sentinel_net::transport::Net;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PillarHealth {
    /// Last day it answered (0: never).
    pub ok_day: u64,
    /// Failed tries in a row.
    pub fails: u32,
    /// Day of the last failure.
    pub fail_day: u64,
}

/// Forget a Pillar after this many failures in a row, when it hasn't
/// answered for this many days.
const FORGET_FAILS: u32 = 6;
const FORGET_DAYS: u64 = 7;

pub fn today() -> u64 {
    sentinel_core::social::coarse_minute() / 1440
}

/// The order to try Pillars in: typed-in addresses first, then a mix of
/// ones that worked lately, vouched ones and built-in seeds (alternating,
/// so the first round has some of each), then the rest; ones that failed
/// twice or more today go last.
pub fn order(hints: &[String], seeds: &[String], known: &[String], vouched: &[String], health: &HashMap<String, PillarHealth>, own: Option<&String>, today: u64) -> Vec<String> {
    let cooling = |p: &String| health.get(p).is_some_and(|h| h.fails >= 2 && h.fail_day == today);
    let mut seen: Vec<String> = Vec::new();
    let mut take = |list: Vec<String>, out: &mut Vec<Vec<String>>| {
        let mut l = Vec::new();
        for p in list {
            if Some(&p) != own && !seen.contains(&p) && !cooling(&p) {
                seen.push(p.clone());
                l.push(p);
            }
        }
        out.push(l);
    };
    let mut groups: Vec<Vec<String>> = Vec::new();
    // Worked within a week, most recent first (random among the same day).
    let mut good: Vec<String> = known.iter().chain(seeds).chain(vouched).filter(|p| health.get(*p).is_some_and(|h| h.ok_day + 7 >= today && h.ok_day > 0)).cloned().collect();
    super::shuffle(&mut good);
    good.sort_by_key(|p| std::cmp::Reverse(health.get(p).map(|h| h.ok_day).unwrap_or(0)));

    let mut v = vouched.to_vec();
    super::shuffle(&mut v);
    let mut s = seeds.to_vec();
    super::shuffle(&mut s);
    let mut hints_g = Vec::new();
    take(hints.to_vec(), &mut hints_g);
    take(good, &mut groups);
    take(v, &mut groups);
    take(s, &mut groups);
    // Interleave good / vouched / seeds.
    let mut mixed: Vec<String> = hints_g.concat();
    let longest = groups.iter().map(Vec::len).max().unwrap_or(0);
    for i in 0..longest {
        for g in &groups {
            if let Some(p) = g.get(i) {
                mixed.push(p.clone());
            }
        }
    }
    // The rest of the known ones, in random order, then the cooling ones.
    let mut rest: Vec<String> = known.iter().filter(|p| Some(*p) != own && !mixed.contains(p) && !cooling(p)).cloned().collect();
    super::shuffle(&mut rest);
    mixed.extend(rest);
    let mut cool: Vec<String> = known.iter().chain(seeds).chain(vouched).filter(|p| Some(*p) != own && cooling(p) && !mixed.contains(p)).cloned().collect();
    cool.dedup();
    mixed.extend(cool);
    mixed
}

/// Note which Pillars answered, and forget ones gone for a week.
pub fn record(s: &mut Store, outcomes: &[(String, bool)], today: u64) {
    for (p, ok) in outcomes {
        let h = s.pillar_health.entry(p.clone()).or_default();
        if *ok {
            h.ok_day = today;
            h.fails = 0;
        } else {
            h.fails = h.fails.saturating_add(1);
            h.fail_day = today;
        }
    }
    let gone: Vec<String> = s
        .pillar_health
        .iter()
        .filter(|(_, h)| h.fails >= FORGET_FAILS && h.ok_day + FORGET_DAYS < today)
        .map(|(p, _)| p.clone())
        .collect();
    for p in gone {
        s.pillar_health.remove(&p);
        s.known_pillars.retain(|k| *k != p);
        s.vouched_pillars.retain(|k| *k != p);
    }
    // Health only for Pillars still known (or built in).
    let seeds = sentinel_net::seed_pillars();
    let keep: Vec<String> = s.known_pillars.iter().chain(s.vouched_pillars.iter()).chain(seeds.iter()).cloned().collect();
    s.pillar_health.retain(|p, _| keep.contains(p));
}

impl Core {
    /// Fetch the credit issuers' vouched lists (checked against the keys
    /// built into Sentinel) and keep them for the next start.
    pub(super) async fn refresh_vouched(&self, net: &Net) {
        let Ok((_, store)) = self.unlocked() else { return };
        let day = today();
        if store.vouched_day == day {
            return;
        }
        let mut all: Vec<String> = Vec::new();
        let mut checked = 0;
        for mint in super::wallet::mints_of(&store) {
            let short: String = mint.chars().take(6).collect();
            let why = async {
                let pk = self.pq_key(&mint).await.map_err(|e| format!("no key ({e:#})"))?;
                let mut s = match tokio::time::timeout(std::time::Duration::from_secs(90), net.connect_hedged(&mint)).await {
                    Ok(Ok(s)) => s,
                    _ => return Err("no answer".to_string()),
                };
                let b = match request(&mut s, &Request::Vouched).await {
                    Ok(Response::Object(b)) => b,
                    Ok(other) => return Err(format!("no list ({other:?})").chars().take(80).collect()),
                    Err(e) => return Err(format!("no list ({e:#})")),
                };
                let v: sentinel_core::directory::SignedVouch = ciborium::from_reader(b.as_slice()).map_err(|_| "unreadable list".to_string())?;
                sentinel_core::directory::check_vouch(&pk, &mint, day, &v).ok_or_else(|| "list failed its signature or date check".to_string())
            };
            match why.await {
                Ok(list) => {
                    checked += 1;
                    for p in list {
                        if sentinel_net::transport::check_onion(&p).is_ok() && !all.contains(&p) {
                            all.push(p);
                        }
                    }
                }
                Err(e) => sentinel_net::note(format!("Sentinel: issuer {short}… vouched list: {e}")),
            }
        }
        sentinel_net::note(format!("Sentinel: {checked} issuer list(s) checked; they vouch for {} Pillar(s)", all.len()));
        let _ = self.update(|s| {
            s.vouched_pillars = all;
            s.vouched_day = day;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(ok_day: u64, fails: u32, fail_day: u64) -> PillarHealth {
        PillarHealth { ok_day, fails, fail_day }
    }

    #[test]
    fn worked_vouched_and_seeds_come_first_failing_ones_last() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let mut health = HashMap::new();
        health.insert("good".to_string(), h(100, 0, 0));
        health.insert("dead".to_string(), h(0, 3, 100));
        let o = order(&s(&["hint"]), &s(&["seed"]), &s(&["good", "dead", "other"]), &s(&["vouched"]), &health, None, 100);
        assert_eq!(&o[..4], &s(&["hint", "good", "vouched", "seed"])[..]);
        assert_eq!(o[4], "other");
        assert_eq!(o.last().unwrap(), "dead", "failing today: last");
        // My own Pillar is never tried.
        let mine = "good".to_string();
        assert!(!order(&[], &s(&["seed"]), &s(&["good"]), &[], &health, Some(&mine), 100).contains(&mine));
    }
}
