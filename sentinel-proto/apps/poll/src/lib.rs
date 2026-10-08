//! Polls: the first Sentinel App, built into Sentinel.
//!
//! Anyone in the room can ask a question with 2–4 options; everyone votes
//! (and can change their vote) until the person who asked closes it.
//! Votes are counted by every member's device, so nobody can fake a result.

use sentinel_app_sdk::{export_app, from_cbor, to_cbor, App, Cmd, Ctx, Part, Viewer};
use serde::{Deserialize, Serialize};

const MAX_QUESTION: usize = 200;
const MAX_OPTION: usize = 80;
const MAX_OPTIONS: usize = 4;
/// Open polls at once, and polls kept in all.
const MAX_OPEN: usize = 20;
const MAX_KEPT: usize = 40;
/// Votes per poll (the state has to stay small).
const MAX_VOTES: usize = 400;

#[derive(Default, Serialize, Deserialize)]
struct State {
    next: u32,
    polls: Vec<Poll>,
}

#[derive(Serialize, Deserialize)]
struct Poll {
    id: u32,
    by: String,
    question: String,
    options: Vec<String>,
    /// (voter, option)
    votes: Vec<(String, u8)>,
    open: bool,
    minute: u64,
}

fn clip(s: &str, max: usize) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(max).collect()
}

struct Polls;

impl App for Polls {
    fn init() -> Vec<u8> {
        to_cbor(&State::default())
    }

    fn apply(state: &[u8], cmd: &Cmd, ctx: &Ctx) -> Option<Vec<u8>> {
        let mut s: State = from_cbor(state)?;
        match cmd.action.as_str() {
            "ask" => {
                let question = clip(cmd.input("question"), MAX_QUESTION);
                let mut options: Vec<String> = Vec::new();
                for i in 1..=MAX_OPTIONS {
                    let o = clip(cmd.input(&format!("option{i}")), MAX_OPTION);
                    if !o.is_empty() && !options.contains(&o) {
                        options.push(o);
                    }
                }
                if question.is_empty() || options.len() < 2 || s.polls.iter().filter(|p| p.open).count() >= MAX_OPEN {
                    return None;
                }
                s.polls.push(Poll { id: s.next, by: ctx.who.clone(), question, options, votes: Vec::new(), open: true, minute: ctx.minute });
                s.next += 1;
                // Forget the oldest closed polls.
                while s.polls.len() > MAX_KEPT {
                    let i = s.polls.iter().position(|p| !p.open)?;
                    s.polls.remove(i);
                }
            }
            "vote" => {
                let (id, choice) = ((cmd.arg >> 8) as u32, (cmd.arg & 0xff) as u8);
                let p = s.polls.iter_mut().find(|p| p.id == id && p.open)?;
                if choice as usize >= p.options.len() {
                    return None;
                }
                match p.votes.iter().position(|(w, _)| *w == ctx.who) {
                    Some(i) if p.votes[i].1 == choice => return None,
                    Some(i) => p.votes[i].1 = choice,
                    None if p.votes.len() < MAX_VOTES => p.votes.push((ctx.who.clone(), choice)),
                    None => return None,
                }
            }
            "close" => {
                let p = s.polls.iter_mut().find(|p| p.id == cmd.arg as u32 && p.open)?;
                if p.by != ctx.who {
                    return None;
                }
                p.open = false;
            }
            _ => return None,
        }
        Some(to_cbor(&s))
    }

    fn view(state: &[u8], viewer: &Viewer) -> Vec<Part> {
        let s: State = from_cbor(state).unwrap_or_default();
        let mut out = vec![Part::Card(vec![
            Part::Title("Ask the room".into()),
            Part::Input { id: "question".into(), label: "Question".into(), max: MAX_QUESTION as u32 },
            Part::Input { id: "option1".into(), label: "Option 1".into(), max: MAX_OPTION as u32 },
            Part::Input { id: "option2".into(), label: "Option 2".into(), max: MAX_OPTION as u32 },
            Part::Input { id: "option3".into(), label: "Option 3 (optional)".into(), max: MAX_OPTION as u32 },
            Part::Input { id: "option4".into(), label: "Option 4 (optional)".into(), max: MAX_OPTION as u32 },
            Part::Button { label: "Start poll".into(), action: "ask".into(), arg: 0, primary: true },
        ])];
        if s.polls.is_empty() {
            out.push(Part::Muted("No polls yet.".into()));
        }
        for p in s.polls.iter().rev() {
            let total = p.votes.len() as u32;
            let mine = p.votes.iter().find(|(w, _)| *w == viewer.who).map(|v| v.1);
            let mut card = vec![Part::Title(p.question.clone()), Part::Row(vec![Part::Muted("Asked by".into()), Part::Member(p.by.clone())])];
            for (i, o) in p.options.iter().enumerate() {
                let value = p.votes.iter().filter(|v| v.1 as usize == i).count() as u32;
                card.push(Part::Bar { label: o.clone(), value, total, mine: mine == Some(i as u8) });
            }
            if p.open {
                let buttons = p
                    .options
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mine != Some(*i as u8))
                    .map(|(i, o)| Part::Button { label: format!("Vote: {o}"), action: "vote".into(), arg: ((p.id as u64) << 8) | i as u64, primary: false })
                    .collect();
                card.push(Part::Row(buttons));
            }
            let votes = if total == 1 { "1 vote".to_string() } else { format!("{total} votes") };
            card.push(Part::Muted(if p.open { format!("{votes} · open") } else { format!("{votes} · closed") }));
            if p.open && p.by == viewer.who {
                card.push(Part::Button { label: "Close poll".into(), action: "close".into(), arg: p.id as u64, primary: false });
            }
            out.push(Part::Card(card));
        }
        out.push(Part::Muted("Votes are counted on every member's device. They aren't secret from the room's members.".into()));
        out
    }
}

export_app!(Polls);
