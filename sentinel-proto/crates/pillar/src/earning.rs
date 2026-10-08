//! Pillars earn credits (spec §13): the mint checks every Pillar it knows
//! at random times, builds each one's reward weight slowly from good days,
//! lets it fall when they stop, and shares a slowly shrinking daily pool in
//! proportion to weight.
//!
//! - **Checks** (over isolated circuits, about 36 a day): the Pillar
//!   answers, and still holds and serves sealed test items the mint stored
//!   there earlier, each asked for again at a random age of 1 to
//!   [`PROBE_MAX_AGE`] days. Test items are signed by a throwaway key and
//!   look like anyone's post, so a Pillar can't keep only recent data, or
//!   only the test items, and still pass.
//! - **Weight** builds over months (time constant [`RAMP_DAYS`]: most of it
//!   after about four months), so starting many Pillars earns little for
//!   months, and a Pillar can't come and go to farm rewards.
//! - **Judged by the day, not the check**: Tor drops some connections, so a
//!   day counts as good when most checks pass ([`GOOD_DAY`]). Bad days are
//!   graduated: one costs about two days of building, a pattern costs a lot,
//!   so someone disrupting an honest Pillar now and then can't get it
//!   punished much, while a Pillar that's often down loses its weight within
//!   weeks. A missing test item (the Pillar answered but had thrown it away)
//!   isn't noise and is treated as a pattern straight away.
//! - **The daily pool** shrinks smoothly (no halvings); each Pillar's share
//!   is proportional to its weight times its recent availability (the
//!   share of checks it passed, averaged over about two weeks), so being
//!   online part of the time earns at most that part, capped per day. Fractions carry over to
//!   the next day, so however many Pillars there are, the whole pool is
//!   paid out and small Pillars still earn. Pillars younger than
//!   [`NEW_DAYS`] share at most [`NEW_SHARE`] of the pool between them, so a
//!   wave of new Pillars run by one person can't take it over quickly.
//! - Rewards are notes paid to the Pillar's own onion address (as Archives
//!   are paid): the mint learns which Pillar earned, never who runs it.
//!   Compute volunteers will be paid the same way once Compute exists.
//!
//! `tests::simulation` plays a year of honest and cheating Pillars against
//! these rules.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Weight builds with this time constant (days) on good days.
pub const RAMP_DAYS: f64 = 40.0;
/// A day counts as good when at least this share of its checks passed
/// (low enough that Tor dropping some connections doesn't make bad days;
/// availability below 100% already earns less through `avail`).
pub const GOOD_DAY: f64 = 0.7;
/// Availability is averaged with this time constant (days).
pub const AVAIL_DAYS: f64 = 14.0;
/// Weight kept after a single bad day (about two days of building lost).
pub const BAD_DAY: f64 = 0.95;
/// After the third bad day within a week.
pub const BAD_WEEK: f64 = 0.80;
/// After the fifth within two weeks, or a missing test item.
pub const BAD_PATTERN: f64 = 0.60;
/// Credit parts per day shared by all Pillars (per mint), at the start.
pub const POOL_START: f64 = 24.0;
/// The pool shrinks with this time constant (days): about half after two
/// years and nine months, with no sudden steps.
pub const POOL_TAU_DAYS: f64 = 1460.0;
/// The day the pool started (2026-10-07).
pub const POOL_START_DAY: u64 = 20_733;
/// Most parts one Pillar earns per day from one mint.
pub const MAX_DAILY: u32 = 3;
/// Below this weight a Pillar earns nothing yet.
pub const MIN_WEIGHT: f64 = 0.05;
/// Test items are asked for again at a random age up to this (days).
/// Pillars need to keep content at least this long to earn (default 60).
pub const PROBE_MAX_AGE: u64 = 30;
/// Most test items a mint keeps on one Pillar at a time (one a day, each
/// asked for within PROBE_MAX_AGE days, plus some waiting for a Pillar
/// that was away).
pub const MAX_PROBES: usize = 40;
/// Pillars younger than this (days)...
pub const NEW_DAYS: u64 = 90;
/// ...share at most this part of the pool between them.
pub const NEW_SHARE: f64 = 0.25;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Score {
    pub weight: f64,
    /// The day the counters below belong to.
    pub day: u64,
    pub checks: u32,
    pub passes: u32,
    /// Bad days (last 14 days).
    pub fail_days: Vec<u64>,
    /// Older format: one test item (moved into `probes`).
    #[serde(default, skip_serializing)]
    pub probe: Option<([u8; 32], u64)>,
    /// The mint's test items on this Pillar: (address, day stored, day to
    /// ask for it again).
    #[serde(default)]
    pub probes: Vec<([u8; 32], u64, u64)>,
    /// Today a test item was missing.
    #[serde(default)]
    pub lost: bool,
    /// Parts owed from past days' shares, delivered on the next visit.
    pub owed: u32,
    /// Fractions of a part earned so far (carried to the next day).
    #[serde(default)]
    pub accrued: f64,
    /// Share of checks passed, averaged over about two weeks.
    #[serde(default = "one")]
    pub avail: f64,
    pub first_day: u64,
}

fn one() -> f64 {
    1.0
}

impl Score {
    /// What the pool is shared by.
    pub fn earning_weight(&self) -> f64 {
        self.weight * self.avail.clamp(0.0, 1.0)
    }

    /// Close the previous day (if any) and start `today`.
    pub fn roll(&mut self, today: u64) {
        if self.first_day == 0 {
            self.first_day = today;
        }
        if let Some((a, d)) = self.probe.take() {
            self.probes.push((a, d, d + 1));
        }
        if self.day < today {
            // A test item still unanswered a day after it was due, on a day
            // the Pillar was otherwise answering (cutting the connection
            // when asked for an item it no longer has): missing.
            if self.passes > 0 && self.probes.iter().any(|p| p.2 < self.day) {
                self.lost = true;
                let d = self.day;
                self.probes.retain(|p| p.2 >= d);
            }
            // A day with no checks (the mint itself was away) counts for
            // nothing either way; a Pillar that's down fails its checks.
            if self.day != 0 && (self.checks > 0 || self.lost) {
                let rate = if self.checks > 0 { self.passes as f64 / self.checks as f64 } else { 0.0 };
                self.avail = if self.weight == 0.0 && self.fail_days.is_empty() && self.avail == 0.0 {
                    rate
                } else {
                    self.avail + (rate - self.avail) * (1.0 - (-1.0 / AVAIL_DAYS).exp())
                };
                if rate >= GOOD_DAY && !self.lost {
                    // Better days build faster (a Pillar that barely passes
                    // builds noticeably slower than one that always does).
                    self.weight += (1.0 - self.weight) * (1.0 - (-1.0 / RAMP_DAYS).exp()) * rate;
                } else {
                    let d = self.day;
                    self.fail_days.push(d);
                    self.fail_days.retain(|x| x + 14 > d);
                    let last_week = self.fail_days.iter().filter(|x| **x + 7 > d).count();
                    self.weight *= if self.lost || self.fail_days.len() >= 5 {
                        BAD_PATTERN
                    } else if last_week >= 3 {
                        BAD_WEEK
                    } else {
                        BAD_DAY
                    };
                }
            }
            self.checks = 0;
            self.passes = 0;
            self.lost = false;
            self.day = today;
        }
        self.fail_days.retain(|d| d + 14 > today);
    }

    /// Record one check's result.
    pub fn record(&mut self, today: u64, passed: bool) {
        self.roll(today);
        self.checks += 1;
        if passed {
            self.passes += 1;
        }
    }

    /// The Pillar answered but no longer had a test item.
    pub fn record_lost(&mut self, today: u64) {
        self.roll(today);
        self.lost = true;
    }

    /// Test items due to be asked for again. Each stays due until it's
    /// answered (`probe_answered`), so a Pillar can't dodge by dropping
    /// the connection.
    pub fn due_probes(&self, today: u64) -> Vec<[u8; 32]> {
        self.probes.iter().filter(|p| p.2 <= today).map(|p| p.0).collect()
    }

    /// The Pillar answered for a test item: it had it, or not.
    pub fn probe_answered(&mut self, addr: [u8; 32], today: u64, had_it: bool) {
        self.probes.retain(|p| p.0 != addr);
        if !had_it {
            self.record_lost(today);
        }
    }

    /// Whether to store a new test item (one a day).
    pub fn wants_probe(&self, today: u64) -> bool {
        !self.probes.iter().any(|p| p.1 == today)
    }

    /// Remember a new test item, to be asked for again at a random age.
    pub fn add_probe(&mut self, addr: [u8; 32], today: u64, random: u64) {
        self.probes.push((addr, today, today + 1 + random % PROBE_MAX_AGE));
        if self.probes.len() > MAX_PROBES {
            self.probes.remove(0);
        }
    }
}

/// Parts shared out today (by one mint).
pub fn pool(today: u64) -> f64 {
    let t = today.saturating_sub(POOL_START_DAY) as f64;
    POOL_START * (-t / POOL_TAU_DAYS).exp()
}

/// Today's shares: in proportion to weight (new Pillars together capped at
/// [`NEW_SHARE`]), at most [`MAX_DAILY`] each, whole parts only; fractions
/// carry over in `accrued`.
pub fn shares(scores: &mut HashMap<String, Score>, today: u64) -> HashMap<String, u32> {
    let is_new = |s: &Score| s.first_day + NEW_DAYS > today;
    let eligible = |s: &Score| s.weight >= MIN_WEIGHT;
    let new_w: f64 = scores.values().filter(|s| eligible(s) && is_new(s)).map(Score::earning_weight).sum();
    let old_w: f64 = scores.values().filter(|s| eligible(s) && !is_new(s)).map(Score::earning_weight).sum();
    if new_w + old_w <= 0.0 {
        return HashMap::new();
    }
    // Scale new Pillars' weight down when they'd take more than NEW_SHARE
    // (unless there's nobody else).
    let new_scale = if old_w > 0.0 && new_w / (new_w + old_w) > NEW_SHARE { NEW_SHARE / (1.0 - NEW_SHARE) * old_w / new_w } else { 1.0 };
    let total = old_w + new_w * new_scale;
    let pool = pool(today);
    let mut out = HashMap::new();
    for (k, s) in scores.iter_mut() {
        if !eligible(s) {
            s.accrued = 0.0;
            continue;
        }
        let w = if is_new(s) { s.earning_weight() * new_scale } else { s.earning_weight() };
        s.accrued = (s.accrued + pool * w / total).min(MAX_DAILY as f64 + 1.0);
        let n = (s.accrued.floor() as u32).min(MAX_DAILY);
        s.accrued -= n as f64;
        if n > 0 {
            out.insert(k.clone(), n);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(days: u64, rate: f64) -> Score {
        let mut s = Score::default();
        let start = POOL_START_DAY;
        for d in 0..days {
            for c in 0..20 {
                s.record(start + d, (c as f64) < rate * 20.0);
            }
        }
        s.roll(start + days);
        s
    }

    #[test]
    fn weight_takes_months_to_build_and_weeks_to_lose() {
        assert!(run(7, 1.0).weight < 0.17, "a week earns little");
        let four_months = run(120, 1.0);
        assert!(four_months.weight > 0.9, "{}", four_months.weight);
        // Barely good days earn less than perfect ones.
        assert!(run(60, 0.75).earning_weight() < run(60, 1.0).earning_weight() * 0.75);
        // Then three weeks offline (every check fails): almost nothing left.
        let mut s = four_months;
        for d in 0..21 {
            for _ in 0..20 {
                s.record(POOL_START_DAY + 120 + d, false);
            }
        }
        s.roll(POOL_START_DAY + 141);
        assert!(s.weight < 0.03, "{}", s.weight);
    }

    #[test]
    fn single_failures_cost_little_patterns_cost_a_lot() {
        // A few dropped connections in a day: still a good day.
        let mut a = run(120, 1.0);
        let w = a.weight;
        for c in 0..20 {
            a.record(POOL_START_DAY + 120, c != 3);
        }
        a.roll(POOL_START_DAY + 121);
        assert!(a.weight >= w);
        // A whole bad day: a little.
        for _ in 0..20 {
            a.record(POOL_START_DAY + 121, false);
        }
        a.roll(POOL_START_DAY + 122);
        assert!(a.weight > w * 0.94);
        // Five bad days in ten: a lot.
        let mut b = run(120, 1.0);
        for d in 0..5 {
            b.record(POOL_START_DAY + 121 + d * 2, false);
        }
        b.roll(POOL_START_DAY + 132);
        assert!(b.weight < w * 0.5, "{}", b.weight);
        // One test item thrown away: a lot at once.
        let mut c = run(120, 1.0);
        c.record(POOL_START_DAY + 120, true);
        c.record_lost(POOL_START_DAY + 120);
        c.roll(POOL_START_DAY + 121);
        assert!(c.weight < w * 0.65);
    }

    #[test]
    fn the_pool_shrinks_smoothly_and_is_shared_by_weight() {
        assert_eq!(pool(POOL_START_DAY), 24.0);
        assert!(pool(POOL_START_DAY + 1000) < 24.0 && pool(POOL_START_DAY + 1000) > 10.0);
        let mut scores = HashMap::new();
        scores.insert("old".to_string(), run(200, 1.0));
        scores.insert("new".to_string(), run(3, 1.0));
        // Many brand-new Pillars together earn nothing yet.
        for i in 0..50 {
            scores.insert(format!("sybil{i}"), run(1, 1.0));
        }
        let s = shares(&mut scores, POOL_START_DAY + 200);
        assert_eq!(s.get("old"), Some(&MAX_DAILY));
        assert!(s.keys().all(|k| !k.starts_with("sybil")));
    }

    #[test]
    fn many_pillars_still_earn() {
        // 100 equal Pillars, 24 parts a day: each earns about one part every
        // four days (fractions carry over), and the pool is paid out.
        let mut scores: HashMap<String, Score> = (0..100).map(|i| (format!("p{i}"), run(200, 1.0))).collect();
        let mut paid = 0;
        for d in 0..40 {
            paid += shares(&mut scores, POOL_START_DAY + 200 + d).values().sum::<u32>();
        }
        let expected: f64 = (0..40).map(|d| pool(POOL_START_DAY + 200 + d)).sum();
        assert!(paid as f64 > expected * 0.95 && paid as f64 <= expected + 1.0, "{paid} of {expected}");
    }

    /// A year of Pillars, honest and not, sharing one mint's pool.
    mod simulation {
        use super::super::*;

        /// Deterministic random numbers (xorshift), so results repeat.
        struct Rng(u64);
        impl Rng {
            fn next(&mut self) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0
            }
            fn chance(&mut self, p: f64) -> bool {
                ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
            }
        }

        #[derive(Clone, Copy, Debug)]
        enum Plan {
            /// Runs all the time; Tor drops this share of checks.
            Honest(f64),
            /// Honest, but down for `.1` days every `.0` days (updates,
            /// power cuts, travel).
            Outages(u64, u64),
            /// Runs `.0` days, then off `.1` days, to save costs.
            Cycles(u64, u64),
            /// Online only this share of each day.
            PartTime(f64),
            /// Answers, but keeps only the last this-many days of data.
            Keeps(u64),
            /// Honest, but an attacker knocks out 30% of its checks on this
            /// many days a week.
            Griefed(u64),
            /// Keeps only this many days of data, and drops the connection
            /// when asked for an item it no longer has.
            Dodges(u64),
            /// Keeps only 3 days of data, and starts over under a new
            /// address every this-many days to escape its record.
            Rotates(u64),
            /// One of a wave of honest Pillars started together.
            Wave,
        }

        struct Sim {
            plan: Plan,
            name: String,
            start: u64,
            score: Score,
            earned: u64,
            /// Earned on days 180..210 (for the wave).
            early: u64,
            /// Test items held: (address, day stored).
            held: Vec<([u8; 32], u64)>,
        }

        const CHECKS: u32 = 36;
        const NOISE: f64 = 0.05;

        fn online(plan: Plan, d: u64, rng: &mut Rng) -> bool {
            match plan {
                Plan::Outages(every, down) => d % every >= down,
                Plan::Cycles(up, down) => d % (up + down) < up,
                Plan::PartTime(p) => rng.chance(p),
                _ => true,
            }
        }

        fn day(sims: &mut [Sim], d: u64, rng: &mut Rng, total_pool: &mut f64) {
            let today = POOL_START_DAY + d;
            for s in sims.iter_mut() {
                if d < s.start {
                    continue;
                }
                if let Plan::Rotates(every) = s.plan {
                    if d > s.start && (d - s.start) % every == 0 {
                        s.score = Score::default();
                        s.held.clear();
                    }
                }
                let keep = match s.plan {
                    Plan::Keeps(n) | Plan::Dodges(n) => n,
                    Plan::Rotates(_) => 3,
                    _ => u64::MAX,
                };
                s.held.retain(|(_, at)| d - at <= keep);
                let grief = matches!(s.plan, Plan::Griefed(n) if d % 7 < n);
                let noise = match s.plan {
                    Plan::Honest(n) => n,
                    _ => NOISE,
                };
                let up_today = online(s.plan, d, rng);
                for _ in 0..CHECKS {
                    let up = if matches!(s.plan, Plan::PartTime(_)) { online(s.plan, d, rng) } else { up_today };
                    let mut passed = up && !rng.chance(noise) && !(grief && rng.chance(0.3));
                    if passed {
                        for addr in s.score.due_probes(today) {
                            let has = s.held.iter().any(|(a, _)| *a == addr);
                            if !has && matches!(s.plan, Plan::Dodges(_)) {
                                passed = false;
                                break;
                            }
                            s.score.probe_answered(addr, today, has);
                        }
                    }
                    if passed {
                        if s.score.wants_probe(today) {
                            let addr: [u8; 32] = std::array::from_fn(|_| rng.next() as u8);
                            s.held.push((addr, d));
                            s.score.add_probe(addr, today, rng.next());
                        }
                    }
                    s.score.record(today, passed);
                }
            }
            // The next morning: shares.
            let tomorrow = today + 1;
            let mut map: HashMap<String, Score> = HashMap::new();
            for s in sims.iter_mut() {
                if d >= s.start {
                    s.score.roll(tomorrow);
                    map.insert(s.name.clone(), std::mem::take(&mut s.score));
                }
            }
            *total_pool += pool(tomorrow);
            let paid = shares(&mut map, tomorrow);
            for s in sims.iter_mut() {
                if let Some(sc) = map.remove(&s.name) {
                    s.score = sc;
                }
                let n = paid.get(&s.name).copied().unwrap_or(0) as u64;
                s.earned += n;
                if (180..210).contains(&d) {
                    s.early += n;
                }
            }
        }

        #[test]
        fn a_year_of_honest_and_cheating_pillars() {
            let mut rng = Rng(0x5eed_1234_abcd_0001);
            let mut plans: Vec<(String, Plan, u64)> = (0..20).map(|i| (format!("honest{i}"), Plan::Honest(NOISE), 0)).collect();
            plans.extend([
                ("flaky Tor (15% of checks fail)".to_string(), Plan::Honest(0.15), 0),
                ("down 3 days a month".to_string(), Plan::Outages(30, 3), 0),
                ("10 days on, 10 off".to_string(), Plan::Cycles(10, 10), 0),
                ("online 85% of the day".to_string(), Plan::PartTime(0.85), 0),
                ("keeps 3 days of data".to_string(), Plan::Keeps(3), 0),
                ("keeps 14 days of data".to_string(), Plan::Keeps(14), 0),
                ("keeps 25 days of data".to_string(), Plan::Keeps(25), 0),
                ("keeps 3 days, dodges the checks".to_string(), Plan::Dodges(3), 0),
                ("griefed 1 day a week".to_string(), Plan::Griefed(1), 0),
                ("griefed 2 days a week".to_string(), Plan::Griefed(2), 0),
                ("keeps 3 days, new address monthly".to_string(), Plan::Rotates(30), 0),
            ]);
            plans.extend((0..60).map(|i| (format!("wave{i}"), Plan::Wave, 180)));
            let mut sims: Vec<Sim> = plans
                .into_iter()
                .map(|(name, plan, start)| Sim { plan, name, start, score: Score::default(), earned: 0, early: 0, held: Vec::new() })
                .collect();
            let mut total_pool = 0.0;
            let mut wave_pool = 0.0;
            for d in 0..365 {
                let before = total_pool;
                day(&mut sims, d, &mut rng, &mut total_pool);
                if (180..210).contains(&d) {
                    wave_pool += total_pool - before;
                }
            }

            let mut honest: Vec<u64> = sims.iter().filter(|s| s.name.starts_with("honest")).map(|s| s.earned).collect();
            honest.sort();
            let base = honest[honest.len() / 2] as f64;
            let rel = |name: &str| sims.iter().find(|s| s.name == name).unwrap().earned as f64 / base;
            println!("\nA year, 36 checks a day, {NOISE:.0e} Tor noise; honest Pillar earned {base} parts (= 100%)");
            for s in sims.iter().filter(|s| !s.name.starts_with("honest") && !s.name.starts_with("wave")) {
                println!("  {:<36} {:>5.0}%", s.name, 100.0 * s.earned as f64 / base);
            }
            let wave_early: u64 = sims.iter().filter(|s| s.name.starts_with("wave")).map(|s| s.early).sum();
            let wave_year: u64 = sims.iter().filter(|s| s.name.starts_with("wave")).map(|s| s.earned).sum();
            let paid: u64 = sims.iter().map(|s| s.earned).sum();
            println!("  60 Pillars started together on day 180: {:.0}% of the pool in their first month, {wave_year} parts by year end", 100.0 * wave_early as f64 / wave_pool);
            println!("  paid {paid} parts of a {total_pool:.0}-part pool");

            // Honest Pillars with ordinary trouble keep most of it.
            assert!(rel("flaky Tor (15% of checks fail)") > 0.8);
            assert!(rel("down 3 days a month") > 0.6);
            // Disruption by someone else costs an honest Pillar only part.
            assert!(rel("griefed 1 day a week") > 0.6);
            assert!(rel("griefed 2 days a week") > 0.35);
            // Saving costs doesn't pay: less than in proportion to the time
            // or storage saved.
            assert!(rel("10 days on, 10 off") < 0.25);
            assert!(rel("online 85% of the day") < 0.85);
            assert!(rel("keeps 3 days of data") < 0.05);
            assert!(rel("keeps 14 days of data") < 0.15);
            assert!(rel("keeps 25 days of data") < 0.4);
            assert!(rel("keeps 3 days, new address monthly") < 0.15);
            assert!(rel("keeps 3 days, dodges the checks") < 0.05);
            // A wave of new Pillars can't take over the pool quickly.
            assert!((wave_early as f64) < wave_pool * NEW_SHARE + 1.0);
            // Never more than the pool.
            assert!(paid as f64 <= total_pool + sims.len() as f64);
        }
    }
}
