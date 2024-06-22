use std::{
    io::{stdout, Write},
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
    }

    /// A NFA (nondeterministic finite automaton) for matching character
    /// strings.
    pub struct Nfa {
        trans: Vec<Vec<Transition>>,
        matches: HashSet<StateId>,
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
            self.trans[start].push(Transition { dest, label })
        }

        /// Follow all epsilon transitions in the given set of states.
        pub fn follow(
            &self,
            states: &Vec<StateId>,
            states_out: &mut Vec<StateId>,
            states_hash_out: &mut HashSet<StateId>,
        ) {
            let mut found = HashSet::<StateId>::new();
            let mut stk = Vec::<StateId>::new();
            stk.extend(states);
            states_out.clear();
            states_hash_out.clear();
            while let Some(elt) = stk.pop() {
                if found.contains(&elt) {
                    continue;
                }
                if self.matches.contains(&elt) && (states_hash_out.insert(elt)) {
                    states_out.push(elt);
                }
                for Transition { dest: state, label } in &self.trans[elt] {
                    match label {
                        Label::None => {
                            stk.push(*state);
                        }
                        _ => {
                            if states_hash_out.insert(elt) {
                                states_out.push(elt);
                            }
                        }
                    }
                }
                found.insert(elt);
            }
        }

        /// Feed a character to the given set of states.
        pub fn feed(
            &self,
            ch: Input,
            states: &Vec<StateId>,
            states_out: &mut Vec<StateId>,
            states_hash_out: &mut HashSet<StateId>,
        ) {
            states_out.clear();
            states_hash_out.clear();
            for state in states {
                for Transition { dest: next, label } in &self.trans[*state] {
                    match label {
                        Label::_ByteRange(min, max) => match ch {
                            Input::Byte(byte) if byte >= *min && byte <= *max => {
                                if states_hash_out.insert(*next) {
                                    states_out.push(*next);
                                }
                            }
                            _ => {}
                        },
                        Label::RuneRange(min, max) => match ch {
                            Input::Rune(rune) if rune >= *min && rune <= *max => {
                                if states_hash_out.insert(*next) {
                                    states_out.push(*next);
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
        ) -> Option<Vec<u8>> {
            let mut states_vec = Vec::<StateId>::new();
            let mut states_vec_next = Vec::<StateId>::new();
            let mut states_hash = HashSet::<StateId>::new();
            let mut options_vec = Vec::<Label>::new();
            let mut options_hash = HashSet::<Label>::new();
            let mut output = Vec::<Input>::new();
            states_vec.push(start);
            states_hash.insert(start);
            loop {
                assert!(!states_vec.is_empty());
                self.follow(&states_vec, &mut states_vec_next, &mut states_hash);
                (states_vec, states_vec_next) = (states_vec_next, states_vec);
                if states_hash.contains(&target)
                    && (states_vec.len() == 1 || rng.gen_range(0..5) == 0)
                {
                    let mut flattened = Vec::<u8>::new();
                    for symbol in output {
                        match symbol {
                            Input::Byte(b) => flattened.push(b),
                            Input::Rune(r) => {
                                let mut ubuf: [u8; 4] = [0; 4];
                                let encoded = r.encode_utf8(&mut ubuf);
                                flattened.extend_from_slice(encoded.as_bytes());
                            }
                        }
                    }
                    return Some(Vec::from_iter(flattened));
                }
                assert!(!states_vec.is_empty());
                options_vec.clear();
                options_hash.clear();
                for state in &states_vec {
                    for Transition { dest: _, label } in &self.trans[*state] {
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
                output.push(next);
                self.feed(next, &states_vec, &mut states_vec_next, &mut states_hash);
                (states_vec, states_vec_next) = (states_vec_next, states_vec);
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
    }

    impl Regex {
        fn _print(&self, indent: usize) {
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
            }
        }

        /// Dump this regex into an NFA, returning start and end states.
        pub fn to_nfa(&self, nfa: &mut Nfa) -> (usize, usize) {
            let start = nfa.new_state();
            let end = nfa.new_state();
            match self {
                Regex::Char(u) => {
                    nfa.link(start, Label::RuneRange(*u, *u), end);
                }
                Regex::Cat(l, r) => {
                    let (l_start, l_end) = l.to_nfa(nfa);
                    let (r_start, r_end) = r.to_nfa(nfa);
                    nfa.link(l_end, Label::None, r_start);
                    nfa.link(start, Label::None, l_start);
                    nfa.link(r_end, Label::None, end);
                }
                Regex::Alt(l, r) => {
                    let (l_start, l_end) = l.to_nfa(nfa);
                    let (r_start, r_end) = r.to_nfa(nfa);
                    nfa.link(start, Label::None, l_start);
                    nfa.link(start, Label::None, r_start);
                    nfa.link(l_end, Label::None, end);
                    nfa.link(r_end, Label::None, end);
                }
                Regex::Quant(r, min, max) => {
                    fn compile_quant(
                        r: &Regex,
                        nfa: &mut Nfa,
                        min: usize,
                        max: Option<usize>,
                    ) -> (usize, usize) {
                        let start = nfa.new_state();
                        let end = nfa.new_state();
                        match (min, max) {
                            (0, None) => {
                                let (r_start, r_end) = r.to_nfa(nfa);
                                nfa.link(start, Label::None, r_start);
                                nfa.link(r_end, Label::None, end);
                                nfa.link(end, Label::None, start);
                            }
                            (0, Some(0)) => {
                                nfa.link(start, Label::None, end);
                            }
                            (0, Some(m)) => {
                                let (r_start, r_end) = r.to_nfa(nfa);
                                nfa.link(start, Label::None, end);
                                nfa.link(start, Label::None, r_start);
                                nfa.link(r_end, Label::None, end);
                                let (d_start, d_end) = compile_quant(r, nfa, 0, Some(m - 1));
                                nfa.link(r_end, Label::None, d_start);
                                nfa.link(d_end, Label::None, end);
                            }
                            (n, m) => {
                                let (r_start, r_end) = r.to_nfa(nfa);
                                nfa.link(start, Label::None, r_start);
                                let (d_start, d_end) =
                                    compile_quant(r, nfa, n - 1, m.map(|m| m - 1));
                                nfa.link(r_end, Label::None, d_start);
                                nfa.link(d_end, Label::None, end);
                            }
                        }
                        (start, end)
                    }
                    let (q_start, q_end) = compile_quant(r, nfa, *min, *max);
                    nfa.link(start, Label::None, q_start);
                    nfa.link(q_end, Label::None, end);
                }
                Regex::Cls(r, lo, hi) => {
                    let label = Label::RuneRange(min(*lo, *hi), max(*lo, *hi));
                    match r {
                        None => {
                            nfa.link(start, label, end);
                        }
                        Some(r) => {
                            let down = nfa.new_state();
                            nfa.link(start, Label::None, down);
                            nfa.link(down, label, end);
                            let (d_start, d_end) = r.to_nfa(nfa);
                            nfa.link(start, Label::None, d_start);
                            nfa.link(d_end, Label::None, end);
                        }
                    }
                }
            }
            (start, end)
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
        let range = if level < 3 { 0..5 } else { 0..1 };
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
            }
        }
    }
}

use std::ffi::{c_char, c_int, c_void};

use crate::nfa::Label;

extern "C" {
    fn bbre_spec_init(
        spec: *mut *mut c_void,
        pat: *const c_char,
        pat_size: usize,
        alloc: *mut c_void,
    ) -> c_int;
    fn bbre_spec_destroy(spec: *mut c_void);
    fn bbre_init_spec(pregex: *mut *mut c_void, spec: *mut c_void, alloc: *mut c_void) -> c_int;
    fn bbre_destroy(regex: *mut c_void);
    fn bbre_match(
        regex: *mut c_void,
        s: *const c_char,
        n: usize,
        pos: usize,
        num_captures: u32,
        captures: *mut u32,
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
    num_spans: u32,
    match_string: Vec<u8>,
    r#match: bool,
    match_spans: Vec<(usize, usize)>,
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
        let (start, stop) = regex.to_nfa(&mut nfa);
        let end = nfa.new_matching_state();
        nfa.link(stop, Label::None, end);
        let serialized_regex = format!("{regex}");
        let example_or_none = nfa.make_example(start, end, &mut rng);
        if example_or_none.is_none() {
            continue;
        }
        let example = example_or_none.unwrap();
        if example.len() > 500 {
            continue;
        }
        let test = Test {
            r#type: "match".to_string(),
            regex: Vec::from(serialized_regex.as_bytes()),
            extra: Extra {
                fuzzington_seed: cli.seed + m - 1,
            },
            num_spans: 0,
            match_string: example.clone(),
            match_spans: Vec::<(usize, usize)>::new(),
            r#match: true,
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
                bbre_init_spec(ptr::addr_of_mut!(c_re_ptr), spec_ptr, null_mut()),
                0
            );
            bbre_spec_destroy(spec_ptr);
            let err = bbre_match(
                c_re_ptr,
                example.as_ptr().cast(),
                example.len(),
                0,
                0,
                null_mut(),
            );
            assert_eq!(err, 1);
            bbre_destroy(c_re_ptr);
        }
        n += 1;
    }
    Ok(())
}
