use std::{
    io::{stdout, Write},
    iter::zip,
    ptr::{self, null_mut},
};

use clap::Parser;
use rand::{rngs::StdRng, SeedableRng};

/// NFA data structure and utilities
mod nfa {
    use rand::{seq::SliceRandom, Rng};
    use std::collections::HashSet;

    type StateId = usize;

    #[derive(Clone, Copy)]
    pub enum Input {
        Byte(u8),
        Rune(char),
    }

    #[derive(PartialEq, Eq, Hash, Clone, Copy)]
    pub enum Label {
        None,
        _ByteRange(u8, u8),
        RuneRange(char, char),
    }

    /// A directed transition. The start state is implied. A label of None is an
    /// epsilon transition.
    struct Transition {
        pub dest: StateId,
        pub label: Label,
        pub save: Option<usize>,
    }

    /// A NFA (nondeterministic finite automaton) for matching character
    /// strings.
    pub struct Nfa {
        trans: Vec<Vec<Transition>>,
        matches: HashSet<StateId>,
    }

    pub struct Thread {
        state_id: StateId,
        saves: Vec<usize>,
    }

    impl Thread {
        pub const UNSET_SLOT: usize = usize::MAX;
        pub fn root(state_id: StateId) -> Thread {
            Thread {
                state_id,
                saves: vec![],
            }
        }

        pub fn fork(&self, state_id: StateId) -> Thread {
            Thread {
                state_id,
                saves: self.saves.clone(),
            }
        }

        pub fn fork_with(&self, state_id: StateId, idx: usize, pos: usize) -> Thread {
            let mut next_saves = self.saves.clone();
            let want_len = ((idx / 2) * 2) + 2;
            while want_len > next_saves.len() {
                next_saves.push(Self::UNSET_SLOT);
            }
            next_saves[idx] = pos;
            Thread {
                state_id,
                saves: next_saves,
            }
        }
    }

    enum FollowSpec {
        Thread(Thread),
        Char(Thread),
    }

    impl Nfa {
        /// Creates an empty NFA.
        pub fn new() -> Nfa {
            Nfa {
                trans: Vec::new(),
                matches: HashSet::new(),
            }
        }

        /// Creates a new state and returns its ID.
        pub fn new_state(&mut self) -> StateId {
            self.trans.push(Vec::new());
            self.trans.len() - 1
        }

        /// Creates a new matching state and returns its ID.
        pub fn new_matching_state(&mut self) -> StateId {
            let state_ref = self.new_state();
            self.matches.insert(state_ref);
            state_ref
        }

        /// Registers a transition for the given state.
        /// If the transition is not an epsilon transition, the state must not
        /// have any existing transitions.
        pub fn link(&mut self, start: StateId, label: Label, dest: StateId) {
            assert!(!matches!(label, Label::None) <= self.trans[start].is_empty());
            assert!(!self.matches.contains(&start));
            self.trans[start].push(Transition {
                dest,
                label,
                save: None,
            })
        }

        pub fn link_with_save(&mut self, start: StateId, save: usize, dest: StateId) {
            self.trans[start].push(Transition {
                dest,
                label: Label::None,
                save: Some(save),
            })
        }

        /// Follow all epsilon transitions in the given set of states.
        pub fn follow(
            &self,
            threads: &mut Vec<Thread>,
            threads_out: &mut Vec<Thread>,
            states_hash_out: &mut HashSet<StateId>,
            pos: usize,
        ) {
            let mut found = HashSet::<StateId>::new();
            let mut stk = Vec::<FollowSpec>::new();
            stk.extend(threads.drain(0..).map(|elt| FollowSpec::Thread(elt)));
            threads_out.clear();
            states_hash_out.clear();
            while let Some(fspec) = stk.pop() {
                match fspec {
                    FollowSpec::Thread(elt) => {
                        if found.contains(&elt.state_id) {
                            continue;
                        }
                        if self.matches.contains(&elt.state_id)
                            && (states_hash_out.insert(elt.state_id))
                        {
                            threads_out.push(elt.fork(elt.state_id));
                            break;
                        }
                        for Transition {
                            dest: state,
                            label,
                            save,
                        } in self.trans[elt.state_id].iter().rev()
                        {
                            match label {
                                Label::None => match save {
                                    None => stk.push(FollowSpec::Thread(elt.fork(*state))),
                                    Some(idx) => stk
                                        .push(FollowSpec::Thread(elt.fork_with(*state, *idx, pos))),
                                },
                                _ => {
                                    stk.push(FollowSpec::Char(elt.fork(elt.state_id)));
                                }
                            }
                        }
                        found.insert(elt.state_id);
                    }
                    FollowSpec::Char(elt) => {
                        if found.contains(&elt.state_id) {
                            continue;
                        }
                        threads_out.push(elt);
                    }
                }
            }
        }

        /// Feed a character to the given set of states.
        pub fn feed(
            &self,
            ch: Input,
            states: &Vec<Thread>,
            states_out: &mut Vec<Thread>,
            states_hash_out: &mut HashSet<StateId>,
        ) {
            states_out.clear();
            states_hash_out.clear();
            for state in states {
                for Transition {
                    dest: next,
                    label,
                    save: _save,
                } in &self.trans[state.state_id]
                {
                    match label {
                        Label::_ByteRange(min, max) => match ch {
                            Input::Byte(byte) if byte >= *min && byte <= *max => {
                                if states_hash_out.insert(*next) {
                                    states_out.push(state.fork(*next));
                                }
                            }
                            _ => {}
                        },
                        Label::RuneRange(min, max) => match ch {
                            Input::Rune(rune) if rune >= *min && rune <= *max => {
                                if states_hash_out.insert(*next) {
                                    states_out.push(state.fork(*next));
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }

        /// Generate an example matching this NFA.
        pub fn make_example<R: Rng + ?Sized>(
            &self,
            start: StateId,
            target: StateId,
            rng: &mut R,
        ) -> Option<(Vec<u8>, Vec<usize>)> {
            let mut threads_vec = Vec::<Thread>::new();
            let mut threads_vec_next = Vec::<Thread>::new();
            let mut states_hash = HashSet::<StateId>::new();
            let mut options_vec = Vec::<Label>::new();
            let mut options_hash = HashSet::<Label>::new();
            let mut flattened = Vec::<u8>::new();
            let mut previous_result: Option<(usize, Vec<usize>)> = None;
            threads_vec.push(Thread::root(start));
            states_hash.insert(start);
            loop {
                assert!(!threads_vec.is_empty());
                self.follow(
                    &mut threads_vec,
                    &mut threads_vec_next,
                    &mut states_hash,
                    flattened.len(),
                );
                (threads_vec, threads_vec_next) = (threads_vec_next, threads_vec);
                for i in 0..threads_vec.len() {
                    if threads_vec[i].state_id == target {
                        if i == 0 {
                            return Some((flattened, threads_vec.remove(i).saves));
                        } else {
                            if previous_result.is_some() && rng.gen_range(0..5) == 4 {
                                // just arbitrarily end the string here
                                let (prev_len, prev_saves) = previous_result.unwrap();
                                flattened.truncate(prev_len);
                                return Some((flattened, prev_saves));
                            }
                            previous_result = Some((flattened.len(), threads_vec[i].saves.clone()));
                            threads_vec.truncate(i);
                            break;
                        }
                    }
                }
                if threads_vec.len() == 0 {
                    if previous_result.is_some() {
                        let (prev_len, prev_saves) = previous_result.unwrap();
                        flattened.truncate(prev_len);
                        return Some((flattened, prev_saves));
                    } else {
                        return None;
                    }
                }
                assert!(!threads_vec.is_empty());
                options_vec.clear();
                options_hash.clear();
                for state in &threads_vec {
                    for Transition {
                        dest: _,
                        label,
                        save: _,
                    } in &self.trans[state.state_id]
                    {
                        match label {
                            Label::None => {}
                            _ => {
                                if options_hash.insert(*label) {
                                    options_vec.push(*label);
                                }
                            }
                        }
                    }
                }
                if options_vec.is_empty() {
                    return None; // threads died -- bad!
                }
                let next = match options_vec.choose(rng).unwrap() {
                    Label::_ByteRange(min, max) => Input::Byte(rng.gen_range(*min..=*max)),
                    Label::RuneRange(min, max) => Input::Rune(rng.gen_range(*min..=*max)),
                    _ => unreachable!(),
                };
                match next {
                    Input::Byte(b) => flattened.push(b),
                    Input::Rune(r) => {
                        let mut ubuf: [u8; 4] = [0; 4];
                        let encoded = r.encode_utf8(&mut ubuf);
                        flattened.extend_from_slice(encoded.as_bytes());
                    }
                }
                self.feed(next, &threads_vec, &mut threads_vec_next, &mut states_hash);
                (threads_vec, threads_vec_next) = (threads_vec_next, threads_vec);
            }
        }
    }
}

/// Data structures and utilities for representing a regex
mod regex {
    use core::fmt;
    use std::cmp::{max, min};

    use crate::nfa::{Label, Nfa};
    use rand::Rng;

    /// Regex AST. Can be losslessly converted into a regex string.
    pub enum Regex {
        Char(char),
        Cat(Box<Regex>, Box<Regex>),
        Alt(Box<Regex>, Box<Regex>),
        Quant(Box<Regex>, usize, Option<usize>),
        Cls(Option<Box<Regex>>, char, char),
        Grp(Box<Regex>),
    }

    impl Regex {
        pub fn _print(&self, indent: usize) {
            print!("{:i$}", "", i = indent);
            match self {
                Regex::Char(u) => println!("Char: {}", u),
                Regex::Cat(l, r) => {
                    println!("Cat:");
                    l._print(indent + 1);
                    r._print(indent + 1);
                }
                Regex::Alt(l, r) => {
                    println!("Alt:");
                    l._print(indent + 1);
                    r._print(indent + 1);
                }
                Regex::Quant(r, min, max) => {
                    println!(
                        "Quant {}-{}:",
                        min,
                        max.map_or("inf".to_string(), |v| v.to_string())
                    );
                    r._print(indent + 1);
                }
                Regex::Cls(r, min, max) => {
                    println!("Cls {}-{}:", min, max);
                    if r.is_some() {
                        r.as_ref().unwrap()._print(indent + 1);
                    }
                }
                Regex::Grp(r) => {
                    println!("Grp:");
                    r._print(indent + 1);
                }
            }
        }

        /// Dump this regex into an NFA, returning start and end states.
        pub fn to_nfa(&self, nfa: &mut Nfa, grp_idx: usize) -> (usize, usize, usize) {
            let start = nfa.new_state();
            let end = nfa.new_state();
            let next_grp_idx;
            match self {
                Regex::Char(u) => {
                    nfa.link(start, Label::RuneRange(*u, *u), end);
                    next_grp_idx = grp_idx;
                }
                Regex::Cat(l, r) => {
                    let (l_start, l_end, ret_grp_idx) = l.to_nfa(nfa, grp_idx);
                    let (r_start, r_end, ret_grp_idx) = r.to_nfa(nfa, ret_grp_idx);
                    nfa.link(l_end, Label::None, r_start);
                    nfa.link(start, Label::None, l_start);
                    nfa.link(r_end, Label::None, end);
                    next_grp_idx = ret_grp_idx;
                }
                Regex::Alt(l, r) => {
                    let (l_start, l_end, ret_grp_idx) = l.to_nfa(nfa, grp_idx);
                    let (r_start, r_end, ret_grp_idx) = r.to_nfa(nfa, ret_grp_idx);
                    nfa.link(start, Label::None, l_start);
                    nfa.link(start, Label::None, r_start);
                    nfa.link(l_end, Label::None, end);
                    nfa.link(r_end, Label::None, end);
                    next_grp_idx = ret_grp_idx;
                }
                Regex::Quant(r, min, max) => {
                    fn compile_quant(
                        r: &Regex,
                        nfa: &mut Nfa,
                        min: usize,
                        max: Option<usize>,
                        grp_idx: usize,
                    ) -> (usize, usize, usize) {
                        let start = nfa.new_state();
                        let end = nfa.new_state();
                        let next_grp_idx: usize;
                        match (min, max) {
                            (0, None) => {
                                let (r_start, r_end, ret_grp_idx) = r.to_nfa(nfa, grp_idx);
                                nfa.link(start, Label::None, r_start);
                                nfa.link(start, Label::None, end);
                                nfa.link(r_end, Label::None, end);
                                nfa.link(end, Label::None, start);
                                next_grp_idx = ret_grp_idx;
                            }
                            (0, Some(0)) => {
                                nfa.link(start, Label::None, end);
                                next_grp_idx = grp_idx;
                            }
                            (0, Some(m)) => {
                                let (r_start, r_end, ret_grp_idx) = r.to_nfa(nfa, grp_idx);
                                nfa.link(start, Label::None, r_start);
                                nfa.link(start, Label::None, end);
                                nfa.link(r_end, Label::None, end);
                                let (d_start, d_end, _) =
                                    compile_quant(r, nfa, 0, Some(m - 1), grp_idx);
                                nfa.link(r_end, Label::None, d_start);
                                nfa.link(d_end, Label::None, end);
                                next_grp_idx = ret_grp_idx;
                            }
                            (n, m) => {
                                let (r_start, r_end, _) = r.to_nfa(nfa, grp_idx);
                                nfa.link(start, Label::None, r_start);
                                let (d_start, d_end, ret_grp_idx) =
                                    compile_quant(r, nfa, n - 1, m.map(|m| m - 1), grp_idx);
                                nfa.link(r_end, Label::None, d_start);
                                nfa.link(d_end, Label::None, end);
                                next_grp_idx = ret_grp_idx
                            }
                        }
                        (start, end, next_grp_idx)
                    }
                    let (q_start, q_end, ret_grp_idx) = compile_quant(r, nfa, *min, *max, grp_idx);
                    nfa.link(start, Label::None, q_start);
                    nfa.link(q_end, Label::None, end);
                    next_grp_idx = ret_grp_idx;
                }
                Regex::Cls(r, lo, hi) => {
                    let label = Label::RuneRange(min(*lo, *hi), max(*lo, *hi));
                    match r {
                        None => {
                            nfa.link(start, label, end);
                            next_grp_idx = grp_idx;
                        }
                        Some(r) => {
                            let down = nfa.new_state();
                            nfa.link(start, Label::None, down);
                            nfa.link(down, label, end);
                            let (d_start, d_end, _) = r.to_nfa(nfa, grp_idx);
                            nfa.link(start, Label::None, d_start);
                            nfa.link(d_end, Label::None, end);
                            next_grp_idx = grp_idx;
                        }
                    }
                }
                Regex::Grp(r) => {
                    let (d_start, d_end, ret_grp_idx) = r.to_nfa(nfa, grp_idx + 2);
                    nfa.link_with_save(start, grp_idx, d_start);
                    nfa.link_with_save(d_end, grp_idx + 1, end);
                    next_grp_idx = ret_grp_idx;
                }
            }
            (start, end, next_grp_idx)
        }
    }

    fn generate_utf_codepoint<R: Rng + ?Sized>(rng: &mut R) -> char {
        match rng.gen_range(1..=4) {
            1 => rng.gen_range('\0'..'\u{7f}'),
            2 => rng.gen_range('\u{80}'..'\u{7ff}'),
            3 => rng.gen_range('\u{800}'..'\u{ffff}'),
            4 => rng.gen_range('\u{10000}'..'\u{10ffff}'),
            _ => unreachable!(),
        }
    }

    fn generate_cls<R: Rng + ?Sized>(rng: &mut R, num_ranges: u32) -> Regex {
        let lo = generate_utf_codepoint(rng);
        let hi = generate_utf_codepoint(rng);
        Regex::Cls(
            if num_ranges > 1 {
                Some(Box::new(generate_cls(rng, num_ranges - 1)))
            } else {
                None
            },
            lo,
            hi,
        )
    }

    pub fn generate_regex<R: Rng + ?Sized>(rng: &mut R, level: u32) -> Regex {
        let range = if level < 3 { 0..6 } else { 0..1 };
        match rng.gen_range(range) {
            0 => Regex::Char(rng.gen_range('\0'..'\u{ff}')),
            1 => Regex::Cat(
                Box::new(generate_regex(rng, level + 1)),
                Box::new(generate_regex(rng, level + 1)),
            ),
            2 => Regex::Alt(
                Box::new(generate_regex(rng, level + 1)),
                Box::new(generate_regex(rng, level + 1)),
            ),
            3 => {
                let qmin = rng.gen_range(0..1);
                let qmax = if rng.gen_range(0..3) < 2 {
                    None
                } else {
                    Some(qmin + rng.gen_range(0..10))
                };
                Regex::Quant(Box::new(generate_regex(rng, level + 1)), qmin, qmax)
            }
            4 => {
                let ranges = rng.gen_range(1..10);
                generate_cls(rng, ranges)
            }
            5 => Regex::Grp(Box::new(generate_regex(rng, level + 1))),
            _ => unreachable!(),
        }
    }

    fn fmt_charclass(
        r: &Option<Box<Regex>>,
        lo: char,
        hi: char,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        fn escape(ch: char, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if "^-[]\\".contains(ch) {
                write!(f, "\\{ch}")
            } else {
                write!(f, "{ch}")
            }
        }
        escape(lo, f)
            .and_then(|_| write!(f, "-"))
            .and_then(|_| escape(hi, f))
            .and_then(|_| match r {
                Some(r_sub_box) => {
                    let r_sub = r_sub_box.as_ref();
                    match r_sub {
                        Regex::Cls(rs, dl, dh) => fmt_charclass(rs, *dl, *dh, f),
                        _ => unreachable!(),
                    }
                }
                None => fmt::Result::Ok(()),
            })
    }

    impl fmt::Display for Regex {
        /// Convert this regex into a string.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Regex::Char(u) => {
                    if "[]|*?+{}()\\^$".contains(*u) {
                        write!(f, "\\{u}")
                    } else {
                        write!(f, "{u}")
                    }
                }
                Regex::Cat(l, r) => match l.as_ref() {
                    Regex::Alt(_, _) => write!(f, "(?:{l})"),
                    _ => write!(f, "{l}"),
                }
                .and_then(|_| match r.as_ref() {
                    Regex::Alt(_, _) => write!(f, "(?:{r})"),
                    _ => write!(f, "{r}"),
                }),
                Regex::Alt(l, r) => write!(f, "{l}|{r}"),
                Regex::Quant(r, min, max) => match r.as_ref() {
                    Regex::Char(_) => write!(f, "{r}"),
                    Regex::Grp(_) => write!(f, "{r}"),
                    _ => write!(f, "(?:{r})"),
                }
                .and_then(|_| match (min, max) {
                    (0, None) => write!(f, "*"),
                    (1, None) => write!(f, "+"),
                    (0, Some(1)) => write!(f, "?"),
                    (lower, None) => write!(f, "{{{lower},}}"),
                    (lower, Some(higher)) => write!(f, "{{{lower},{higher}}}"),
                }),
                Regex::Cls(r, lo, hi) => write!(f, "[")
                    .and_then(|_| fmt_charclass(r, *lo, *hi, f))
                    .and_then(|_| write!(f, "]")),
                Regex::Grp(r) => write!(f, "(")
                    .and_then(|_| write!(f, "{r}"))
                    .and_then(|_| write!(f, ")")),
            }
        }
    }
}

use std::ffi::{c_char, c_int, c_void};

use crate::nfa::Label;

#[repr(C)]
struct BbreSpan {
    begin: usize,
    end: usize,
}
extern "C" {
    fn bbre_spec_init(
        spec: *mut *mut c_void,
        pat: *const c_char,
        pat_size: usize,
        alloc: *mut c_void,
    ) -> c_int;
    fn bbre_spec_destroy(spec: *mut c_void);
    fn bbre_init(pregex: *mut *mut c_void, spec: *mut c_void, alloc: *mut c_void) -> c_int;
    fn bbre_destroy(regex: *mut c_void);
    fn bbre_which_captures(
        regex: *mut c_void,
        s: *const c_char,
        n: usize,
        captures: *mut BbreSpan,
        did_match: *mut c_int,
        num_captures: c_int,
    ) -> c_int;
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    // Number of test cases to generate
    #[arg(short, long, default_value_t = 1)]
    number: u64,

    // Seed for the random number generator
    #[arg(short, long, default_value_t = 0)]
    seed: u64,
}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Extra {
    fuzzington_seed: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct Test {
    r#type: String,
    extra: Extra,
    regex: Vec<u8>,
    text: Vec<u8>,
    did_match: Vec<bool>,
    spans: Vec<(usize, usize)>,
}

fn main() -> std::io::Result<()> {
    let cli = Args::parse();
    let mut n = 0;
    let mut m = 0;
    loop {
        if n == cli.number {
            break;
        }
        let mut rng = StdRng::seed_from_u64(cli.seed + m);
        m += 1;
        let regex = regex::generate_regex(&mut rng, 0);
        let mut nfa = nfa::Nfa::new();
        let (start, stop, _) = regex.to_nfa(&mut nfa, 0);
        let end = nfa.new_matching_state();
        nfa.link(stop, Label::None, end);
        let serialized_regex = format!("{regex}");
        let example_or_none = nfa.make_example(start, end, &mut rng);
        if example_or_none.is_none() {
            continue;
        }
        let (example, saves) = example_or_none.unwrap();
        if example.len() > 500 {
            continue;
        }
        assert!(saves.len() % 2 == 0);
        let mut match_spans = Vec::<(usize, usize)>::new();
        let mut found_spans = Vec::<BbreSpan>::new();
        let mut did_match = Vec::<bool>::new();
        let mut found_did_match = Vec::<c_int>::new();
        match_spans.push((0, example.len()));
        found_spans.push(BbreSpan { begin: 0, end: 0 });
        did_match.push(true);
        found_did_match.push(1);
        for idx in (0..saves.len()).step_by(2) {
            if saves[idx] == nfa::Thread::UNSET_SLOT || saves[idx + 1] == nfa::Thread::UNSET_SLOT {
                match_spans.push((0, 0));
                did_match.push(false);
            } else {
                match_spans.push((saves[idx], saves[idx + 1]));
                did_match.push(true);
            }
            found_spans.push(BbreSpan { begin: 0, end: 0 });
            found_did_match.push(0);
        }
        let test = Test {
            r#type: "match".to_string(),
            regex: Vec::from(serialized_regex.as_bytes()),
            extra: Extra {
                fuzzington_seed: cli.seed + m - 1,
            },
            text: example.clone(),
            spans: match_spans.clone(),
            did_match: did_match.clone(),
        };
        println!("{}", serde_json::to_string(&test).unwrap());
        stdout().flush().unwrap();
        unsafe {
            let mut spec_ptr: *mut c_void = null_mut();
            assert_eq!(
                bbre_spec_init(
                    ptr::addr_of_mut!(spec_ptr),
                    serialized_regex.as_ptr().cast(),
                    serialized_regex.len(),
                    null_mut(),
                ),
                0
            );
            let mut c_re_ptr: *mut c_void = null_mut();
            assert_eq!(
                bbre_init(ptr::addr_of_mut!(c_re_ptr), spec_ptr, null_mut()),
                0
            );
            bbre_spec_destroy(spec_ptr);
            let err = bbre_which_captures(
                c_re_ptr,
                example.as_ptr().cast(),
                example.len(),
                found_spans.as_mut_ptr(),
                found_did_match.as_mut_ptr(),
                found_spans.len().try_into().unwrap(),
            );
            assert_eq!(err, 1);
            bbre_destroy(c_re_ptr);
        }
        for ((span, (begin, end)), (dm, fdm)) in zip(
            zip(&found_spans, &match_spans),
            zip(&did_match, &found_did_match),
        ) {
            assert_eq!(span.begin, *begin);
            assert_eq!(span.end, *end);
            assert_eq!(if *dm { 1 } else { 0 }, *fdm);
        }
        n += 1;
    }
    Ok(())
}
